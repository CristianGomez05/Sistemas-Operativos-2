#!/usr/bin/env bash
# Seguridad focalizada: HAProxy, Docker, GlusterFS (+checks básicos Galera/MariaDB y Redis)
# Recolecta evidencias en ./seguridad_reporte-YYYYmmdd_HHMMSS
# Probado en Ubuntu Server 22.04/24.04

set -euo pipefail

# -------- Config por defecto (puedes sobreescribir con flags) --------
ROLE="${ROLE:-auto}"  # auto|processing|storage
IPS_PROCESSING_DEFAULT="100.25.217.104,23.22.16.147"
IPS_STORAGE_DEFAULT="23.22.172.33,54.221.141.223"
IPS_PROCESSING="${IPS_PROCESSING:-$IPS_PROCESSING_DEFAULT}"
IPS_STORAGE="${IPS_STORAGE:-$IPS_STORAGE_DEFAULT}"

# Puertos/servicios relevantes (alineados a tu documento de hardening y stack)  :contentReference[oaicite:1]{index=1}
PORTS_HAPROXY_WEB="80,443"
PORTS_GLUSTER_TCP="24007,24008,49152-49251"
PORTS_SWARM_TCP="2377,7946"
PORTS_SWARM_UDP="7946,4789"
PORTS_DB_TCP="3306"
PORT_VRRP_PROTO="112"     # VRRP usa IP protocolo 112

# -------- Parseo de flags simples --------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --role) ROLE="$2"; shift 2 ;;
    --ips-processing) IPS_PROCESSING="$2"; shift 2 ;;
    --ips-storage) IPS_STORAGE="$2"; shift 2 ;;
    *) echo "Opción desconocida: $1" >&2; exit 1 ;;
  esac
done

# -------- Pre-chequeos --------
if [[ $EUID -ne 0 ]]; then
  echo "Ejecuta como root (sudo)." >&2
  exit 1
fi

if ! command -v lsb_release >/dev/null 2>&1; then
  apt-get update -y && apt-get install -y lsb-release
fi

OS="$(lsb_release -ds || echo Ubuntu)"
echo "[INFO] Sistema: $OS"

TS="$(date +'%Y%m%d_%H%M%S')"
OUTDIR="seguridad_reporte-${TS}"
mkdir -p "$OUTDIR"/{haproxy,docker,gluster,db,redis,red,aux}

log() { echo "[$(date +'%H:%M:%S')] $*"; }

# -------- Instalación de herramientas mínimas --------
log "Instalando herramientas requeridas…"
apt-get update -y
DEBS=(
  curl wget jq git make gcc gawk bc
  nmap sslscan openssl
  hping3 iperf3
  netcat-openbsd
  # análisis HTTP y carga controlada:
  apache2-utils
  # pruebas HTTP lentas:
  slowhttptest
)
apt-get install -y "${DEBS[@]}" || true

# testssl.sh (TLS/cifras)
if [[ ! -x /usr/local/bin/testssl.sh ]]; then
  git clone --depth=1 https://github.com/drwetter/testssl.sh /opt/testssl.sh >/dev/null 2>&1 || true
  ln -sf /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh || true
fi

# Trivy (escaneo de imágenes/FS)
if ! command -v trivy >/dev/null 2>&1; then
  curl -fsSL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin >/dev/null 2>&1 || true
fi

# Dockle (linter de buenas prácticas de imágenes)
if ! command -v dockle >/dev/null 2>&1; then
  DOCKLE_URL="$(curl -fsSL https://api.github.com/repos/goodwithtech/dockle/releases/latest | jq -r '.assets[] | select(.name|test("Linux_.*64.tar.gz$")) | .browser_download_url' | head -n1 || true)"
  if [[ -n "${DOCKLE_URL:-}" ]]; then
    TMPD="$(mktemp -d)"; pushd "$TMPD" >/dev/null
    wget -q "$DOCKLE_URL" -O dockle.tgz && tar xzf dockle.tgz
    install -m 0755 dockle /usr/local/bin/dockle
    popd >/dev/null
    rm -rf "$TMPD"
  fi
fi

# Docker Bench for Security (se ejecuta como contenedor)
DOCKER_BENCH_IMAGE="docker/docker-bench-security"

# -------- Detección de rol si AUTO --------
if [[ "$ROLE" == "auto" ]]; then
  if systemctl is-active --quiet glusterd || command -v gluster >/dev/null 2>&1; then
    ROLE="storage"
  elif systemctl is-active --quiet haproxy || command -v docker >/dev/null 2>&1; then
    ROLE="processing"
  else
    ROLE="processing"  # por defecto
  fi
fi
log "Rol detectado/seleccionado: $ROLE"

# -------- Utilidades de red (escaneos controlados) --------
comma_to_nl() { tr ',' '\n' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | sed '/^$/d'; }

scan_host_ports() {
  local host="$1" ports="$2" outfile="$3"
  nmap -Pn -sS -p "$ports" --reason --open -oN "$outfile" "$host" || true
}

scan_host_tls() {
  local host="$1" port="$2" outdir="$3"
  testssl.sh --openssl=openssl --fast --hints --severity MEDIUM --logfile "${outdir}/testssl_${host}_${port}.log" "${host}:${port}" || true
  sslscan --no-failed --show-ciphers --show-certificate "${host}:${port}" > "${outdir}/sslscan_${host}_${port}.txt" 2>&1 || true
}

# -------- PRUEBAS: HAProxy (processing) --------
test_haproxy_local() {
  log "[HAProxy] Validando configuración local…"
  if command -v haproxy >/dev/null 2>&1; then
    haproxy -vv > "$OUTDIR/haproxy/haproxy_version.txt" 2>&1 || true
    if [[ -f /etc/haproxy/haproxy.cfg ]]; then
      haproxy -c -f /etc/haproxy/haproxy.cfg > "$OUTDIR/haproxy/haproxy_cfg_check.txt" 2>&1 || true
    fi
    systemctl status haproxy --no-pager > "$OUTDIR/haproxy/haproxy_status.txt" 2>&1 || true
  else
    echo "HAProxy no instalado en este nodo." > "$OUTDIR/haproxy/nota.txt"
  fi
}

test_haproxy_remote() {
  log "[HAProxy] Pruebas HTTP/HTTPS y cabeceras…"
  local hosts; hosts="$(echo "$IPS_PROCESSING" | comma_to_nl)"
  for h in $hosts; do
    for p in 80 443; do
      # Encabezados y políticas básicas
      timeout 8 bash -c "curl -ksS -D - http://${h}:${p}/ -o /dev/null" > "$OUTDIR/haproxy/headers_${h}_${p}.txt" 2>&1 || true
      timeout 8 bash -c "curl -ksS -D - https://${h}:${p}/ -o /dev/null" > "$OUTDIR/haproxy/headersTLS_${h}_${p}.txt" 2>&1 || true
      # TLS/cifras
      scan_host_tls "$h" "$p" "$OUTDIR/haproxy"
    done

    # Escaneo de puertos expuestos relevantes
    scan_host_ports "$h" "${PORTS_HAPROXY_WEB},${PORTS_SWARM_TCP},${PORTS_DB_TCP}" "$OUTDIR/haproxy/ports_${h}.nmap"

    # Prueba de HTTP lento (Slowloris-like controlada)
    slowhttptest -c 200 -H -i 10 -r 200 -t GET -u "http://${h}/" -x 120 -p 3 \
      > "$OUTDIR/haproxy/slowhttptest_${h}.txt" 2>&1 || true

    # Prueba auth básica en backends (si expone / o /health)
    timeout 8 bash -c "curl -ksS https://${h}/health || curl -ksS http://${h}/health" \
      > "$OUTDIR/haproxy/health_${h}.txt" 2>&1 || true
  done
}

# -------- PRUEBAS: Docker (processing) --------
test_docker_local() {
  log "[Docker] Chequeos locales…"
  if ! command -v docker >/dev/null 2>&1; then
    echo "Docker no instalado en este nodo." > "$OUTDIR/docker/nota.txt"
    return 0
  fi

  docker version > "$OUTDIR/docker/version.txt" 2>&1 || true
  docker info > "$OUTDIR/docker/info.txt" 2>&1 || true

  # Config sensible (rootless/userns, live-restore, log-driver, iptables)
  DOCKERD_JSON="${DOCKERD_JSON:-/etc/docker/daemon.json}"
  if [[ -f "$DOCKERD_JSON" ]]; then
    jq . "$DOCKERD_JSON" > "$OUTDIR/docker/daemon.json.pretty" 2>/dev/null || cp "$DOCKERD_JSON" "$OUTDIR/docker/daemon.json.pretty"
  fi

  # Contenedores con privilegios/capacidades/hostNetwork
  docker ps --all --format 'table {{.ID}}\t{{.Image}}\t{{.Command}}\t{{.Status}}\t{{.Ports}}\t{{.Names}}' > "$OUTDIR/docker/ps_all.txt" 2>&1 || true
  docker inspect $(docker ps -q) > "$OUTDIR/docker/inspect_running.json" 2>/dev/null || true
  docker inspect $(docker ps -aq) > "$OUTDIR/docker/inspect_all.json" 2>/dev/null || true
  grep -E '"Privileged": true|"NetworkMode": "host"|CAP_SYS_ADMIN|cap_add' "$OUTDIR/docker/inspect_all.json" \
    > "$OUTDIR/docker/flags_riesgo.txt" 2>/dev/null || true

  # Docker Bench for Security
  log "[Docker] Ejecutando Docker Bench for Security…"
  docker pull "$DOCKER_BENCH_IMAGE" >/dev/null 2>&1 || true
  docker run --net host --pid host --userns host --cap-add audit_control \
    -e DOCKER_CONTENT_TRUST=1 \
    -v /etc:/etc:ro -v /usr/bin/docker-containerd:/usr/bin/docker-containerd:ro \
    -v /usr/bin/docker-runc:/usr/bin/docker-runc:ro \
    -v /var/lib:/var/lib:ro -v /var/run/docker.sock:/var/run/docker.sock:ro \
    -v /usr/lib/systemd:/usr/lib/systemd:ro -v /etc/systemd:/etc/systemd:ro \
    --label docker_bench_security \
    "$DOCKER_BENCH_IMAGE" > "$OUTDIR/docker/docker-bench-security.txt" 2>&1 || true

  # Escaneo de imágenes locales
  log "[Docker] Escaneando imágenes locales con Trivy y Dockle…"
  docker images --format '{{.Repository}}:{{.Tag}}' | sed '/^<none>:/d' > "$OUTDIR/docker/images_list.txt" || true
  while read -r img; do
    [[ -z "$img" ]] && continue
    trivy image --quiet --no-progress --severity CRITICAL,HIGH "$img" > "$OUTDIR/docker/trivy_${img//[:\/]/_}.txt" 2>&1 || true
    dockle -f json "$img" > "$OUTDIR/docker/dockle_${img//[:\/]/_}.json" 2>&1 || true
  done < "$OUTDIR/docker/images_list.txt"
}

# -------- PRUEBAS: GlusterFS (storage) --------
test_gluster_local() {
  log "[GlusterFS] Chequeos locales…"
  if ! command -v gluster >/dev/null 2>&1; then
    echo "GlusterFS CLI no instalado en este nodo." > "$OUTDIR/gluster/nota.txt"
    return 0
  fi

  systemctl status glusterd --no-pager > "$OUTDIR/gluster/glusterd_status.txt" 2>&1 || true
  gluster --version > "$OUTDIR/gluster/version.txt" 2>&1 || true
  gluster peer status > "$OUTDIR/gluster/peer_status.txt" 2>&1 || true
  gluster volume list > "$OUTDIR/gluster/vol_list.txt" 2>&1 || true

  while read -r vol; do
    [[ -z "$vol" ]] && continue
    gluster volume info "$vol" > "$OUTDIR/gluster/${vol}_info.txt" 2>&1 || true
    gluster volume get "$vol" all > "$OUTDIR/gluster/${vol}_get_all.txt" 2>&1 || true
    gluster volume status "$vol" detail > "$OUTDIR/gluster/${vol}_status.txt" 2>&1 || true
    # Señales de seguridad recomendables:
    egrep -i 'auth.allow|server.ssl|client.ssl|auth.reject|features.quorum|cluster.quorum-type|network.ping-timeout|storage.owner-uid|storage.owner-gid' \
      "$OUTDIR/gluster/${vol}_get_all.txt" > "$OUTDIR/gluster/${vol}_seguridad_opciones.txt" 2>/dev/null || true
    gluster volume heal "$vol" info > "$OUTDIR/gluster/${vol}_heal.txt" 2>&1 || true
  done < <(gluster volume list 2>/dev/null || true)
}

test_gluster_remoto() {
  log "[GlusterFS] Escaneo de exposición de puertos en nodos de almacenamiento…"
  local hosts; hosts="$(echo "$IPS_STORAGE" | comma_to_nl)"
  for h in $hosts; do
    scan_host_ports "$h" "${PORTS_GLUSTER_TCP}" "$OUTDIR/gluster/ports_${h}.nmap"
    # Detección de TLS en glusterd (si se configuró SSL)
    scan_host_tls "$h" "24007" "$OUTDIR/gluster"
  done
}

# -------- PRUEBAS: DB/Redis (exposición básica) --------
test_db_redis_exposure() {
  log "[DB/Redis] Validando exposición de 3306 y 6379 en nodos de procesamiento…"
  local hosts; hosts="$(echo "$IPS_PROCESSING" | comma_to_nl)"
  for h in $hosts; do
    scan_host_ports "$h" "${PORTS_DB_TCP},6379" "$OUTDIR/red/ports_db_redis_${h}.nmap"
    # Intento seguro (no intrusivo) de banner grab
    timeout 5 bash -c "echo | timeout 4 openssl s_client -connect ${h}:3306 -tls1_2" \
      > "$OUTDIR/db/mysql_tls_${h}.txt" 2>&1 || true
    (echo -en 'PING\r\n'; sleep 1) | nc -w2 "$h" 6379 > "$OUTDIR/redis/ping_${h}.txt" 2>&1 || true
  done
}

# -------- PRUEBAS: Red (VRRP, Swarm) --------
test_network() {
  log "[Red] Swarm y VRRP exposición…"
  local hosts_p hosts_s
  hosts_p="$(echo "$IPS_PROCESSING" | comma_to_nl)"
  hosts_s="$(echo "$IPS_STORAGE" | comma_to_nl)"
  for h in $hosts_p; do
    scan_host_ports "$h" "${PORTS_SWARM_TCP}" "$OUTDIR/red/ports_swarm_tcp_${h}.nmap"
    nmap -Pn -sU -p "${PORTS_SWARM_UDP}" --reason -oN "$OUTDIR/red/ports_swarm_udp_${h}.nmap" "$h" || true
  done
  # VRRP protocolo 112 (check básico con nmap)
  for h in $hosts_p; do
    nmap -Pn -sO --packet-trace --reason "$h" | tee "$OUTDIR/red/protocol_scan_${h}.txt" >/dev/null 2>&1 || true
    # Nota: sO lista protocolos IP; buscamos referencia a 112 (VRRP) manualmente
    grep -E '112.*VRRP|VRRP' "$OUTDIR/red/protocol_scan_${h}.txt" > "$OUTDIR/red/vrrp_hint_${h}.txt" 2>/dev/null || true
  done
}

# -------- Ejecución por rol --------
case "$ROLE" in
  processing)
    test_haproxy_local
    test_haproxy_remote
    test_docker_local
    test_db_redis_exposure
    test_network
    ;;
  storage)
    test_gluster_local
    test_gluster_remoto
    test_network
    ;;
  *)
    echo "Rol inválido: $ROLE" >&2; exit 2 ;;
esac

# -------- Resumen rápido --------
SUMMARY="$OUTDIR/RESUMEN.txt"
{
  echo "======== RESUMEN DE PRUEBAS ($TS) ========"
  echo "Rol: $ROLE"
  echo "- Evidencias en: $OUTDIR"
  echo
  if [[ -d "$OUTDIR/haproxy" ]]; then
    echo "[HAProxy]"
    grep -HnE 'X-Frame-Options|Content-Security-Policy|Strict-Transport-Security|Referrer-Policy' "$OUTDIR/haproxy"/headers*.txt 2>/dev/null || echo "  * Revisar headers_*.txt"
    echo "  * TLS: ver testssl_*.log y sslscan_*.txt"
    echo "  * Slow HTTP: ver slowhttptest_*.txt"
    echo
  fi
  if [[ -d "$OUTDIR/docker" ]]; then
    echo "[Docker]"
    echo "  * Bench: docker-bench-security.txt (buscar WARN/INFO/FAIL)"
    echo "  * Imágenes: trivy_*.txt (CRITICAL/HIGH) y dockle_*.json"
    echo "  * Flags de riesgo: flags_riesgo.txt"
    echo
  fi
  if [[ -d "$OUTDIR/gluster" ]]; then
    echo "[GlusterFS]"
    echo "  * Puertos: ports_*.nmap"
    echo "  * TLS/SSL en glusterd: testssl_*_24007.log / sslscan_*_24007.txt"
    echo "  * Volúmenes: *_info.txt, *_get_all.txt (auth.allow/client.ssl/server.ssl/quorum)"
    echo "  * Heal/Split-brain: *_heal.txt"
    echo
  fi
  if [[ -d "$OUTDIR/db" || -d "$OUTDIR/redis" ]]; then
    echo "[DB/Redis]"
    echo "  * MySQL/MariaDB TLS: mysql_tls_*.txt"
    echo "  * Redis ping/banner: redis/ping_*.txt (si responde sin auth -> riesgo)"
    echo
  fi
  echo "[Red]"
  echo "  * Swarm TCP/UDP: ports_swarm_*.nmap"
  echo "  * VRRP indicios: vrrp_hint_*.txt"
  echo
  echo "Siguiente paso: revisar archivos y cerrar hallazgos en configuración (headers, TLS, auth, exposición de puertos, privilegios de contenedores, auth.allow y SSL en Gluster, etc.)."
} > "$SUMMARY"

log "Listo. Revisa el directorio: $OUTDIR"
