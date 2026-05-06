import secrets

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from app.config import API_PASSWORD, API_USERNAME
from app.schemas import (
    DisconnectResponse,
    MessageResponse,
    PortForwardCreateRequest,
    PortForwardRule,
    ProxyRoute,
    ProxyRouteCreateRequest,
    SubdomainAvailability,
    UserCreateRequest,
)
from app.services.port_forward import (
    PortForwardError,
    create_rule,
    delete_rule,
    init_db,
    list_rules,
    restore_rules_from_db,
)
from app.services.proxy import (
    ProxyError,
    check_subdomain_availability,
    create_route,
    delete_route,
    init_db as init_proxy_db,
    list_routes,
)
from app.services.users import UserServiceError, create_user, delete_user, disable_user, disconnect_user, enable_user

security = HTTPBasic()


def require_auth(credentials: HTTPBasicCredentials = Depends(security)) -> None:
    if not API_USERNAME or not API_PASSWORD:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="API credentials belum dikonfigurasi di server",
        )
    ok_user = secrets.compare_digest(credentials.username.encode(), API_USERNAME.encode())
    ok_pass = secrets.compare_digest(credentials.password.encode(), API_PASSWORD.encode())
    if not (ok_user and ok_pass):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Username atau password salah",
            headers={"WWW-Authenticate": "Basic"},
        )


app = FastAPI(title="VPN API Management", version="1.0.0")


@app.on_event("startup")
def on_startup() -> None:
    init_db()
    init_proxy_db()
    # Restore iptables rules dari DB saat service restart/reboot
    restore_rules_from_db()


@app.get("/health", response_model=MessageResponse)
def health(_: None = Depends(require_auth)) -> MessageResponse:
    return MessageResponse(message="ok")


@app.post("/users", response_model=MessageResponse)
def api_create_user(payload: UserCreateRequest, _: None = Depends(require_auth)) -> MessageResponse:
    try:
        create_user(payload.username, payload.password, str(payload.ip))
        return MessageResponse(message="User berhasil dibuat")
    except UserServiceError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.delete("/users/{username}", response_model=MessageResponse)
def api_delete_user(username: str, _: None = Depends(require_auth)) -> MessageResponse:
    try:
        delete_user(username)
        return MessageResponse(message="User berhasil dihapus")
    except UserServiceError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/users/{username}/disconnect", response_model=DisconnectResponse)
def api_disconnect_user(username: str, _: None = Depends(require_auth)) -> DisconnectResponse:
    try:
        count = disconnect_user(username)
        return DisconnectResponse(
            message="Permintaan disconnect diproses",
            disconnected_sessions=count,
        )
    except UserServiceError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/users/{username}/disable", response_model=MessageResponse)
def api_disable_user(username: str, _: None = Depends(require_auth)) -> MessageResponse:
    try:
        disable_user(username)
        return MessageResponse(message="User berhasil di-disable")
    except UserServiceError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/users/{username}/enable", response_model=MessageResponse)
def api_enable_user(username: str, _: None = Depends(require_auth)) -> MessageResponse:
    try:
        enable_user(username)
        return MessageResponse(message="User berhasil di-enable")
    except UserServiceError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/port-forwardings", response_model=list[PortForwardRule])
def api_list_port_forwardings(_: None = Depends(require_auth)) -> list[PortForwardRule]:
    rules = list_rules()
    return [
        PortForwardRule(
            name=r.name,
            protocol=r.protocol,
            listen_port=r.listen_port,
            destination_ip=r.destination_ip,
            destination_port=r.destination_port,
            created_at=r.created_at,
        )
        for r in rules
    ]


@app.post("/port-forwardings", response_model=PortForwardRule)
def api_create_port_forwarding(payload: PortForwardCreateRequest, _: None = Depends(require_auth)) -> PortForwardRule:
    try:
        rule = create_rule(
            name=payload.name,
            protocol=payload.protocol,
            listen_port=payload.listen_port,
            destination_ip=str(payload.destination_ip),
            destination_port=payload.destination_port,
        )
        return PortForwardRule(
            name=rule.name,
            protocol=rule.protocol,
            listen_port=rule.listen_port,
            destination_ip=rule.destination_ip,
            destination_port=rule.destination_port,
            created_at=rule.created_at,
        )
    except PortForwardError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.delete("/port-forwardings/{name}", response_model=MessageResponse)
def api_delete_port_forwarding(name: str, _: None = Depends(require_auth)) -> MessageResponse:
    try:
        delete_rule(name)
        return MessageResponse(message="Rule port forwarding dihapus")
    except PortForwardError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/proxy-routes", response_model=list[ProxyRoute])
def api_list_proxy_routes(_: None = Depends(require_auth)) -> list[ProxyRoute]:
    routes = list_routes()
    return [
        ProxyRoute(
            name=r.name,
            subdomain=r.subdomain,
            domain=r.domain,
            port_forward_name=r.port_forward_name,
            upstream_ip=r.upstream_ip,
            upstream_port=r.upstream_port,
            ssl_enabled=bool(r.ssl_enabled),
            created_at=r.created_at,
        )
        for r in routes
    ]


@app.get("/proxy-routes/check-subdomain/{subdomain}", response_model=SubdomainAvailability)
def api_check_subdomain_availability(subdomain: str, _: None = Depends(require_auth)) -> SubdomainAvailability:
    try:
        check = check_subdomain_availability(subdomain)
        return SubdomainAvailability(
            subdomain=check.subdomain,
            domain=check.domain,
            available=check.available,
            exists_in_db=check.exists_in_db,
            exists_in_dns=check.exists_in_dns,
            dns_checked=check.dns_checked,
            dns_records=check.dns_records,
            reason=check.reason,
        )
    except ProxyError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/proxy-routes", response_model=ProxyRoute)
def api_create_proxy_route(payload: ProxyRouteCreateRequest, _: None = Depends(require_auth)) -> ProxyRoute:
    try:
        route = create_route(
            name=payload.name,
            subdomain=payload.subdomain,
            port_forward_name=payload.port_forward_name,
        )
        return ProxyRoute(
            name=route.name,
            subdomain=route.subdomain,
            domain=route.domain,
            port_forward_name=route.port_forward_name,
            upstream_ip=route.upstream_ip,
            upstream_port=route.upstream_port,
            ssl_enabled=bool(route.ssl_enabled),
            created_at=route.created_at,
        )
    except ProxyError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.delete("/proxy-routes/{name}", response_model=MessageResponse)
def api_delete_proxy_route(name: str, _: None = Depends(require_auth)) -> MessageResponse:
    try:
        delete_route(name)
        return MessageResponse(message="Proxy route dihapus")
    except ProxyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
