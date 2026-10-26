#!/usr/bin/env bash
# Build release artifacts into dist/.
#
#   scripts/build.sh [--version X.Y.Z] [--skip-web] [--server-arch "amd64 arm64"] [--packages]
#
# Steps: web UI (Vite) -> agents (linux/amd64, linux/arm64, windows/amd64)
# -> agent .deb/.rpm/.msi packages (nfpm, wixl; skipped when the tool is missing)
# -> agents and agent packages embedded into the server (with a manifest)
# -> server binaries -> SHA256SUMS.
# An MSI is built with wixl (msitools) when available.
# --packages also builds the server .deb and .rpm (amd64 and
# arm64), fetching nfpm with `go run` if it is not installed, and builds the
# server for both architectures. Server packages are never embedded.
set -euo pipefail
cd "$(dirname "$0")/.."

# ---- Names: the only place product, binary and package names are defined. ----
# Each can be overridden from the environment (the CI workflow does this).
PRODUCT_TITLE="${PRODUCT_TITLE:-Sentrel}"
AGENT_BIN="${AGENT_BIN:-sentrel-agent}"        # binary name, ./cmd/<AGENT_BIN>
SERVER_BIN="${SERVER_BIN:-sentrel-server}"     # binary name, ./cmd/<SERVER_BIN>
AGENT_PKG="${AGENT_PKG:-$AGENT_BIN}"             # deb/rpm package names
SERVER_PKG="${SERVER_PKG:-$SERVER_BIN}"
AGENT_USER="${AGENT_USER:-sentrel-agent}"      # system user
SERVER_USER="${SERVER_USER:-sentrel}"
SERVER_UNIT="${SERVER_UNIT:-sentrel}"          # systemd unit name of the server
FW_TABLE="${FW_TABLE:-sentrel}"                # nft table created by the agent
GO_MODULE="${GO_MODULE:-sentrel}"              # module path in go.mod
HOMEPAGE="${HOMEPAGE:-https://github.com/XEDigital/Sentrel}"
DOCS_URL="${DOCS_URL:-$HOMEPAGE}"
MAINTAINER="${MAINTAINER:-Sentrel maintainers <noreply@users.noreply.github.com>}"
LICENSE="${LICENSE:-Apache-2.0}"
NFPM_VERSION="${NFPM_VERSION:-v2.41.3}"
# Install locations. The agent path is referenced by the sudoers rule.
AGENT_PATH="${AGENT_PATH:-/usr/local/bin/$AGENT_BIN}"
SERVER_PATH="${SERVER_PATH:-/usr/local/bin/$SERVER_BIN}"
AGENT_ETC="${AGENT_ETC:-/etc/$AGENT_BIN}"
AGENT_STATE="${AGENT_STATE:-/var/lib/$AGENT_BIN}"
AGENT_SHARE="${AGENT_SHARE:-/usr/share/$AGENT_BIN}"
SERVER_DATA="${SERVER_DATA:-/var/lib/$SERVER_UNIT}"
# -----------------------------------------------------------------------------

VERSION="${VERSION:-}"
SKIP_WEB=0
PACKAGES=0
SERVER_ARCHES="amd64"
while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --skip-web) SKIP_WEB=1; shift ;;
    --server-arch) SERVER_ARCHES="$2"; shift 2 ;;
    --packages) PACKAGES=1; shift ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done
PKG_ARCHES="${PKG_ARCHES:-amd64 arm64}"   # architectures to package
[ "$PACKAGES" = 1 ] && SERVER_ARCHES="$PKG_ARCHES"
if [ -z "$VERSION" ]; then
  VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo "0.0.0-dev")
fi
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo none)
DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS="-s -w -X $GO_MODULE/internal/version.Version=${VERSION#v} -X $GO_MODULE/internal/version.Commit=$COMMIT -X $GO_MODULE/internal/version.Date=$DATE"
export CGO_ENABLED=0

mkdir -p dist
echo "==> version $VERSION"

if [ "$SKIP_WEB" = 0 ]; then
  echo "==> web UI"
  (cd web && { [ -d node_modules ] || npm ci --no-audit --no-fund; } && npm run build)
fi
[ -f web/dist/index.html ] || { echo "web/dist missing: build the UI or drop --skip-web" >&2; exit 1; }

echo "==> agents"
find server/agentdist/bin -type f ! -name README.txt ! -name .gitignore -delete
for target in linux/amd64 linux/arm64 windows/amd64; do
  os=${target%/*}; arch=${target#*/}
  out="dist/$AGENT_BIN-$os-$arch"
  [ "$os" = windows ] && out="$out.exe"
  GOOS=$os GOARCH=$arch go build -trimpath -ldflags "$LDFLAGS" -o "$out" ./cmd/$AGENT_BIN
  cp "$out" server/agentdist/bin/
  echo "    $out ($(du -h "$out" | cut -f1))"
done
echo "$VERSION" > server/agentdist/bin/VERSION

rm -f dist/"$AGENT_BIN"-*.msi
if command -v wixl >/dev/null 2>&1; then
  echo "==> MSI"
  sed "s/@VERSION@/$(echo "$VERSION" | sed -E 's/^v//; s/[^0-9.].*$//; s/^$/0.0.0/')/" deploy/windows/agent.wxs > dist/agent.wxs
  (cd dist && wixl -a x64 -o "$AGENT_BIN-${VERSION#v}-x64.msi" agent.wxs && rm agent.wxs)
fi

# ---- Agent packages (.deb, .rpm, .msi) ---------------------------------------
# Built before the server so they can be embedded and offered for download on
# the Agents page. Missing tools just mean fewer packages in the manifest.
PKGDIR=server/agentdist/bin/pkg
rm -rf "$PKGDIR" server/agentdist/bin/packages.json
rm -f dist/"$AGENT_PKG"[_-]*.deb dist/"$AGENT_PKG"[_-]*.rpm
mkdir -p "$PKGDIR"

NFPM_CMD=""
if command -v nfpm >/dev/null 2>&1 && [ -z "${NFPM_USE_GO_RUN:-}" ]; then
  NFPM_CMD=nfpm
elif [ "$PACKAGES" = 1 ] || [ -n "${NFPM_USE_GO_RUN:-}" ]; then
  NFPM_CMD="go run github.com/goreleaser/nfpm/v2/cmd/nfpm@$NFPM_VERSION"
fi

STAGE="$PWD/dist/.pkgstage"
if [ -n "$NFPM_CMD" ] || [ "$PACKAGES" = 1 ]; then
  rm -rf "$STAGE"; mkdir -p "$STAGE/bin"
  cp -r deploy/packages/agent deploy/packages/server "$STAGE/"
  # Substitute the @NAME@ placeholders with the names defined above.
  subst="$STAGE/subst.sed"; : > "$subst"
  for v in PRODUCT_TITLE AGENT_BIN SERVER_BIN AGENT_PKG SERVER_PKG AGENT_USER SERVER_USER SERVER_UNIT \
           FW_TABLE HOMEPAGE DOCS_URL MAINTAINER LICENSE AGENT_PATH SERVER_PATH AGENT_ETC AGENT_STATE \
           AGENT_SHARE SERVER_DATA STAGE; do
    val=$(printf '%s' "${!v}" | sed 's/[\&|]/\&/g')
    printf "s|@%s@|%s|g
" "$v" "$val" >> "$subst"
  done
  find "$STAGE/agent" "$STAGE/server" -type f -exec sed -i -f "$subst" {} +
fi

if [ -n "$NFPM_CMD" ]; then
  echo "==> agent packages (nfpm)"
  for arch in $PKG_ARCHES; do
    cp "dist/$AGENT_BIN-linux-$arch" "$STAGE/bin/"
    sed "s|@ARCH@|$arch|g" "$STAGE/agent/nfpm.yaml" > "$STAGE/agent/nfpm-$arch.yaml"
    for fmt in deb rpm; do
      ARCH=$arch VERSION="${VERSION#v}" $NFPM_CMD package --config "$STAGE/agent/nfpm-$arch.yaml" --packager $fmt --target dist/ >/dev/null
    done
  done
else
  echo "==> agent packages skipped: nfpm not found (install it, or pass --packages)"
fi

# Collect the packages into the embedded directory and describe them.
for f in dist/"$AGENT_PKG"[_-]*.deb dist/"$AGENT_PKG"[_-]*.rpm dist/"$AGENT_BIN"-*.msi; do
  if [ -f "$f" ]; then cp "$f" "$PKGDIR/"; fi
done
manifest="["; sep=""
for f in "$PKGDIR"/*; do
  [ -f "$f" ] || continue
  name=$(basename "$f")
  case "$name" in
    *.deb) fmt=deb; os=linux ;;
    *.rpm) fmt=rpm; os=linux ;;
    *.msi) fmt=msi; os=windows ;;
    *) continue ;;
  esac
  case "$name" in
    *amd64*|*x86_64*|*x64*) parch=amd64 ;;
    *arm64*|*aarch64*) parch=arm64 ;;
    *) continue ;;
  esac
  manifest="$manifest$sep{\"file\":\"$name\",\"os\":\"$os\",\"arch\":\"$parch\",\"format\":\"$fmt\",\"size\":$(stat -c %s "$f"),\"sha256\":\"$(sha256sum "$f" | cut -d' ' -f1)\"}"
  sep=","
  echo "    $name ($(du -h "$f" | cut -f1))"
done
echo "$manifest]" > server/agentdist/bin/packages.json

echo "==> server"
for arch in $SERVER_ARCHES; do
  out="dist/$SERVER_BIN-linux-$arch"
  GOOS=linux GOARCH=$arch go build -trimpath -ldflags "$LDFLAGS" -o "$out" ./cmd/$SERVER_BIN
  echo "    $out ($(du -h "$out" | cut -f1))"
done
cp deploy/linux/install-server.sh deploy/linux/install-agent.sh deploy/windows/install-agent.ps1 dist/

if [ "$PACKAGES" = 1 ]; then
  echo "==> server packages (nfpm $NFPM_VERSION)"
  for arch in $PKG_ARCHES; do
    cp "dist/$SERVER_BIN-linux-$arch" "$STAGE/bin/"
    sed "s|@ARCH@|$arch|g" "$STAGE/server/nfpm.yaml" > "$STAGE/server/nfpm-$arch.yaml"
    for fmt in deb rpm; do
      ARCH=$arch VERSION="${VERSION#v}" $NFPM_CMD package --config "$STAGE/server/nfpm-$arch.yaml" --packager $fmt --target dist/
    done
  done
fi
rm -rf "$STAGE"

(cd dist && sha256sum "$AGENT_BIN"* "$SERVER_BIN"* install-* > SHA256SUMS)
echo "==> done: dist/"
