package app

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
)

// Perm is a permission checked by API routes.
type Perm int

const (
	PermNone         Perm = iota // authenticated, no specific permission
	PermRead                     // view hosts, alerts, metrics
	PermAck                      // acknowledge / unack alerts
	PermMonitoring               // checks, thresholds, maintenance, notifications, status pages, groups
	PermHosts                    // enrol, delete, SNMP devices
	PermHostSettings             // per-host options and remote-action opt-ins
	PermJobs                     // upgrades, IP blocks, vulnerability scans
	PermUsers                    // manage users (own tenant for tenant admins)
	PermTenants                  // manage tenants
	PermSettings                 // global settings
	PermBranding                 // branding (own tenant for tenant admins)
	PermAudit                    // read the audit log
)

var permNames = map[Perm]string{
	PermNone: "authenticated", PermRead: "read", PermAck: "ack", PermMonitoring: "monitoring", PermHosts: "hosts",
	PermHostSettings: "host_settings", PermJobs: "jobs", PermUsers: "users", PermTenants: "tenants",
	PermSettings: "settings", PermBranding: "branding", PermAudit: "audit",
}

// Roles.
const (
	RoleAdmin        = "admin"
	RoleOperator     = "operator"
	RoleViewer       = "viewer"
	RoleTenantAdmin  = "tenant_admin"
	RoleTenantViewer = "tenant_viewer"
)

var rolePerms = map[string][]Perm{
	RoleAdmin:        {PermRead, PermAck, PermMonitoring, PermHosts, PermHostSettings, PermJobs, PermUsers, PermTenants, PermSettings, PermBranding, PermAudit},
	RoleOperator:     {PermRead, PermAck, PermMonitoring, PermHosts, PermHostSettings, PermJobs},
	RoleViewer:       {PermRead},
	RoleTenantAdmin:  {PermRead, PermAck, PermMonitoring, PermHostSettings, PermJobs, PermUsers, PermBranding, PermAudit},
	RoleTenantViewer: {PermRead},
}

// ValidRole reports whether role is allowed for a user in tenant t.
func ValidRole(role string, tenant int64) bool {
	if tenant == 0 {
		return role == RoleAdmin || role == RoleOperator || role == RoleViewer
	}
	return role == RoleTenantAdmin || role == RoleTenantViewer
}

// API key scopes.
var scopePerms = map[string][]Perm{
	"read":  {PermRead},
	"write": {PermRead, PermAck, PermMonitoring, PermHostSettings},
	"jobs":  {PermRead, PermJobs},
	"admin": {PermRead, PermAck, PermMonitoring, PermHosts, PermHostSettings, PermJobs, PermUsers, PermTenants, PermSettings, PermBranding, PermAudit},
}

// Principal is the authenticated caller.
type Principal struct {
	UserID     *int64
	Name       string
	Role       string
	TenantID   int64
	IP         string
	APIKeyID   int64
	SessionID  string
	MFAPending bool // a second factor must be verified or enrolled
	MFAEnroll  bool // policy requires enrolling a second factor (vs verifying one)
	// MustChangePW restricts the session to changing the password (see
	// routeDef.PWOK). API keys of such a user are rejected outright.
	MustChangePW bool
	CSRF         string
	perms        map[Perm]bool
}

func newPrincipal(role string, scopes []string) map[Perm]bool {
	m := map[Perm]bool{PermNone: true}
	for _, p := range rolePerms[role] {
		m[p] = true
	}
	if scopes != nil {
		allowed := map[Perm]bool{PermNone: true}
		for _, s := range scopes {
			for _, p := range scopePerms[s] {
				allowed[p] = true
			}
		}
		for p := range m {
			if !allowed[p] {
				delete(m, p)
			}
		}
	}
	return m
}

// Has reports whether the principal holds a permission.
func (p *Principal) Has(perm Perm) bool { return p != nil && p.perms[perm] }

// CanTenant reports whether the principal may access rows of tenant t.
func (p *Principal) CanTenant(t int64) bool { return p != nil && (p.TenantID == 0 || p.TenantID == t) }

// IsProvider reports whether the principal belongs to the provider tenant.
func (p *Principal) IsProvider() bool { return p != nil && p.TenantID == 0 }

// Perms lists permission names (for the UI).
func (p *Principal) Perms() []string {
	var out []string
	for k := range p.perms {
		if k != PermNone {
			out = append(out, permNames[k])
		}
	}
	return out
}

func systemPrincipal(name string, tenant int64) *Principal {
	return &Principal{Name: name, Role: RoleAdmin, TenantID: 0, perms: newPrincipal(RoleAdmin, nil)}
}

// --- errors ---

type apiError struct {
	Status int    `json:"-"`
	Code   string `json:"code"`
	Msg    string `json:"error"`
}

func (e *apiError) Error() string { return e.Msg }

func badRequest(format string, a ...any) error {
	return &apiError{Status: 400, Code: "bad_request", Msg: fmt.Sprintf(format, a...)}
}
func forbidden(msg string) error    { return &apiError{Status: 403, Code: "forbidden", Msg: msg} }
func unauthorized(msg string) error { return &apiError{Status: 401, Code: "unauthorized", Msg: msg} }
func conflict(msg string) error     { return &apiError{Status: 409, Code: "conflict", Msg: msg} }

func writeError(w http.ResponseWriter, err error) {
	var ae *apiError
	switch {
	case errors.As(err, &ae):
	case errors.Is(err, errNotFound), errors.Is(err, sql.ErrNoRows):
		ae = &apiError{Status: 404, Code: "not_found", Msg: "not found"}
	case errors.Is(err, ErrConfirmation):
		ae = &apiError{Status: 409, Code: "confirmation_required", Msg: err.Error()}
	case strings.Contains(err.Error(), "UNIQUE constraint failed"):
		ae = &apiError{Status: 409, Code: "conflict", Msg: "an item with that name already exists"}
	default:
		ae = &apiError{Status: 500, Code: "internal", Msg: "internal server error"}
	}
	writeJSON(w, ae.Status, ae)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// --- request context ---

// Ctx carries a request through a handler.
type Ctx struct {
	a *App
	W http.ResponseWriter
	R *http.Request
	P *Principal
}

func (c *Ctx) ctx() context.Context { return c.R.Context() }

// Decode reads a JSON body into v.
func (c *Ctx) Decode(v any) error {
	dec := json.NewDecoder(io.LimitReader(c.R.Body, 16<<20))
	if err := dec.Decode(v); err != nil {
		if errors.Is(err, io.EOF) {
			return badRequest("request body required")
		}
		return badRequest("invalid JSON: %v", err)
	}
	return nil
}

// ID returns the {id} path parameter.
func (c *Ctx) ID() int64 {
	v, _ := strconv.ParseInt(chi.URLParam(c.R, "id"), 10, 64)
	return v
}

// Param returns a path parameter.
func (c *Ctx) Param(n string) string { return chi.URLParam(c.R, n) }

// Q returns a query parameter.
func (c *Ctx) Q(n string) string { return c.R.URL.Query().Get(n) }

// QInt returns an integer query parameter or def.
func (c *Ctx) QInt(n string, def int64) int64 {
	if v, err := strconv.ParseInt(c.Q(n), 10, 64); err == nil {
		return v
	}
	return def
}

// queryLimit bounds an untrusted integer before any narrowing conversion or allocation.
func (c *Ctx) queryLimit(name string, def, max int) int {
	n, err := strconv.Atoi(c.Q(name))
	if err != nil || n <= 0 {
		return def
	}
	if n > max {
		return max
	}
	return n
}

// tenantWhere returns a SQL condition restricting col to the caller's
// visible tenants, honouring ?tenant_id= for provider users.
func (c *Ctx) tenantWhere(col string) (string, []any) {
	if c.P.TenantID != 0 {
		return col + "=?", []any{c.P.TenantID}
	}
	if t := c.Q("tenant_id"); t != "" {
		if id, err := strconv.ParseInt(t, 10, 64); err == nil {
			return col + "=?", []any{id}
		}
	}
	return "1=1", nil
}

// tenantFor returns the tenant id new objects should belong to: the
// caller's tenant, or a provider-chosen tenant.
func (c *Ctx) tenantFor(requested int64) (int64, error) {
	if c.P.TenantID != 0 {
		return c.P.TenantID, nil
	}
	if requested != 0 {
		var n int
		if err := c.a.db.GetContext(c.ctx(), &n, `SELECT COUNT(*) FROM tenants WHERE id=?`, requested); err != nil || n == 0 {
			return 0, badRequest("unknown tenant")
		}
	}
	return requested, nil
}

func (c *Ctx) audit(action, targetType, targetID string, details any) {
	c.a.audit(c.ctx(), auditEntry{TenantID: c.P.TenantID, UserID: c.P.UserID, Actor: c.P.Name, Action: action,
		TargetType: targetType, TargetID: targetID, Details: details, IP: c.P.IP})
}

// auditT records an audit entry attributed to a specific tenant.
func (c *Ctx) auditT(tenant int64, action, targetType, targetID string, details any) {
	c.a.audit(c.ctx(), auditEntry{TenantID: tenant, UserID: c.P.UserID, Actor: c.P.Name, Action: action,
		TargetType: targetType, TargetID: targetID, Details: details, IP: c.P.IP})
}

// --- routing ---

type handlerFunc func(c *Ctx) (any, error)

type routeDef struct {
	Method  string
	Path    string
	Summary string
	Tag     string
	Perm    Perm
	Public  bool // no authentication
	MFAOK   bool // allowed while MFA is pending
	// PWOK allows the route while a forced password change is outstanding.
	PWOK bool
	// Interactive restricts the route to an interactive cookie session: API
	// keys are refused whatever their scope. Used for account security.
	Interactive bool
	Req         any
	Resp        any
	Query       []string
}

type apiRouter struct {
	a    *App
	mux  chi.Router
	defs []routeDef
}

func (r *apiRouter) add(d routeDef, h handlerFunc) {
	r.defs = append(r.defs, d)
	r.mux.MethodFunc(d.Method, d.Path, func(w http.ResponseWriter, req *http.Request) {
		p := principalFrom(req)
		if !d.Public {
			if p == nil {
				writeError(w, unauthorized("authentication required"))
				return
			}
			if p.MustChangePW && !d.PWOK {
				writeError(w, &apiError{Status: 403, Code: "password_change_required", Msg: "you must change your password before continuing"})
				return
			}
			if d.Interactive && p.APIKeyID != 0 {
				writeError(w, &apiError{Status: 403, Code: "interactive_session_required", Msg: "this action needs a signed-in browser session; API keys cannot do it"})
				return
			}
			if p.MFAPending && !d.MFAOK {
				writeError(w, &apiError{Status: 401, Code: "mfa_required", Msg: "second factor required"})
				return
			}
			if !p.Has(d.Perm) {
				writeError(w, forbidden("you do not have permission for this action"))
				return
			}
		}
		c := &Ctx{a: r.a, W: w, R: req, P: p}
		out, err := h(c)
		if err != nil {
			var ae *apiError
			if !errors.As(err, &ae) && !errors.Is(err, errNotFound) && !errors.Is(err, sql.ErrNoRows) && !errors.Is(err, ErrConfirmation) {
				r.a.log.Error("api error", "method", req.Method, "path", req.URL.Path, "err", err)
			}
			writeError(w, err)
			return
		}
		if out == nil {
			if req.Method == http.MethodGet {
				writeJSON(w, 200, map[string]any{})
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if raw, ok := out.(rawResponse); ok {
			raw(w)
			return
		}
		status := 200
		if req.Method == http.MethodPost {
			if _, ok := out.(created); ok {
				status = 201
			}
		}
		if cr, ok := out.(created); ok {
			out = cr.v
		}
		writeJSON(w, status, out)
	})
}

// rawResponse lets a handler write the response itself.
type rawResponse func(w http.ResponseWriter)

// created wraps a body returned with 201.
type created struct{ v any }

type ctxKey int

const principalKey ctxKey = 1

func principalFrom(r *http.Request) *Principal {
	p, _ := r.Context().Value(principalKey).(*Principal)
	return p
}

// --- OpenAPI ---

func (r *apiRouter) openAPI(serverURL string) map[string]any {
	paths := map[string]map[string]any{}
	schemas := map[string]any{}
	for _, d := range r.defs {
		p := "/api/v1" + d.Path
		if paths[p] == nil {
			paths[p] = map[string]any{}
		}
		op := map[string]any{"summary": d.Summary, "tags": []string{d.Tag}, "operationId": opID(d)}
		var params []map[string]any
		for _, seg := range strings.Split(d.Path, "/") {
			if strings.HasPrefix(seg, "{") {
				name := strings.Trim(seg, "{}")
				params = append(params, map[string]any{"name": name, "in": "path", "required": true, "schema": map[string]any{"type": "string"}})
			}
		}
		for _, q := range d.Query {
			params = append(params, map[string]any{"name": q, "in": "query", "schema": map[string]any{"type": "string"}})
		}
		if params != nil {
			op["parameters"] = params
		}
		if d.Req != nil {
			op["requestBody"] = map[string]any{"required": true, "content": map[string]any{"application/json": map[string]any{"schema": schemaRef(reflect.TypeOf(d.Req), schemas)}}}
		}
		resp := map[string]any{"description": "OK"}
		if d.Resp != nil {
			resp["content"] = map[string]any{"application/json": map[string]any{"schema": schemaRef(reflect.TypeOf(d.Resp), schemas)}}
		}
		op["responses"] = map[string]any{"200": resp, "400": map[string]any{"description": "Bad request"}, "401": map[string]any{"description": "Unauthenticated"}, "403": map[string]any{"description": "Forbidden"}}
		if d.Public {
			op["security"] = []any{}
		} else {
			op["description"] = "Requires permission: " + permNames[d.Perm]
		}
		paths[p][strings.ToLower(d.Method)] = op
	}
	return map[string]any{
		"openapi": "3.0.3",
		"info": map[string]any{"title": "Sentrel API", "version": "1",
			"description": "Every UI action uses this API. Authenticate with a session cookie (plus X-CSRF-Token header) or an API key: `Authorization: Bearer sentrel_...`."},
		"servers": []map[string]any{{"url": strings.TrimRight(serverURL, "/")}},
		"paths":   paths,
		"components": map[string]any{
			"schemas": schemas,
			"securitySchemes": map[string]any{
				"apiKey":  map[string]any{"type": "http", "scheme": "bearer"},
				"session": map[string]any{"type": "apiKey", "in": "cookie", "name": sessionCookie},
			},
		},
		"security": []any{map[string]any{"apiKey": []string{}}, map[string]any{"session": []string{}}},
	}
}

func opID(d routeDef) string {
	s := strings.ToLower(d.Method) + strings.NewReplacer("/", "_", "{", "", "}", "", "-", "_").Replace(d.Path)
	return s
}

func schemaRef(t reflect.Type, schemas map[string]any) map[string]any {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Slice, reflect.Array:
		if t.Elem().Kind() == reflect.Uint8 {
			return map[string]any{"type": "string"}
		}
		return map[string]any{"type": "array", "items": schemaRef(t.Elem(), schemas)}
	case reflect.Map:
		return map[string]any{"type": "object", "additionalProperties": schemaRef(t.Elem(), schemas)}
	case reflect.Struct:
		if t.Name() == "" {
			return structSchema(t, schemas)
		}
		name := t.Name()
		if _, ok := schemas[name]; !ok {
			schemas[name] = map[string]any{} // break cycles
			schemas[name] = structSchema(t, schemas)
		}
		return map[string]any{"$ref": "#/components/schemas/" + name}
	case reflect.String:
		return map[string]any{"type": "string"}
	case reflect.Bool:
		return map[string]any{"type": "boolean"}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return map[string]any{"type": "integer"}
	case reflect.Float32, reflect.Float64:
		return map[string]any{"type": "number"}
	case reflect.Interface:
		return map[string]any{}
	}
	return map[string]any{}
}

func structSchema(t reflect.Type, schemas map[string]any) map[string]any {
	props := map[string]any{}
	if t == reflect.TypeOf(JSON{}) {
		return map[string]any{}
	}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		tag := f.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name := strings.Split(tag, ",")[0]
		if f.Anonymous && name == "" {
			if s, ok := structSchema(f.Type, schemas)["properties"].(map[string]any); ok {
				for k, v := range s {
					props[k] = v
				}
			}
			continue
		}
		if name == "" {
			name = f.Name
		}
		if f.Type == reflect.TypeOf(JSON{}) {
			props[name] = map[string]any{"description": "arbitrary JSON"}
			continue
		}
		props[name] = schemaRef(f.Type, schemas)
	}
	return map[string]any{"type": "object", "properties": props}
}
