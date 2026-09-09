"""Template Registry and Selection Manager.

Provides template lookup, listing, category filtering, and automated recommendation
based on discovered target technologies, open ports, and banners.
"""

from typing import Optional, List, Dict, Any

try:
    from .definitions import BUILTIN_TEMPLATES, ScanTemplate
except Exception:
    from templates.definitions import BUILTIN_TEMPLATES, ScanTemplate


class TemplateRegistry:
    def __init__(self) -> None:
        self._templates: dict[str, ScanTemplate] = {t.id: t for t in BUILTIN_TEMPLATES}

    def list_templates(self, category: Optional[str] = None) -> list[ScanTemplate]:
        if category:
            return [t for t in self._templates.values() if t.category.lower() == category.lower()]
        return list(self._templates.values())

    def get_template(self, template_id: str) -> Optional[ScanTemplate]:
        return self._templates.get(template_id)

    def register_template(self, template: ScanTemplate) -> None:
        self._templates[template.id] = template

    def get_default_template(self) -> ScanTemplate:
        for t in self._templates.values():
            if t.is_default:
                return t
        return self._templates["web_owasp_deep_audit"]

    def list_categories(self) -> list[str]:
        seen = []
        for t in self._templates.values():
            if t.category not in seen:
                seen.append(t.category)
        return seen

    def recommend_template_for_tech(self, technologies: list[str], open_ports: Optional[list[int]] = None) -> ScanTemplate:
        """Heuristic recommendation engine when LLM is unavailable or for rule-based fast match."""
        tech_lower = [t.lower() for t in technologies]
        joined = " ".join(tech_lower)

        # 1. CMS & Framework Specific Matches
        if "wordpress" in joined or "wp-" in joined or "woocommerce" in joined:
            return self._templates["cms_wordpress_deep_audit"]
        if "drupal" in joined:
            return self._templates["cms_drupal_audit"]
        if "joomla" in joined:
            return self._templates["cms_joomla_audit"]
        if "django" in joined or "python" in joined:
            return self._templates["framework_django_audit"]
        if "laravel" in joined or "blade" in joined or "livewire" in joined:
            return self._templates["framework_laravel_audit"]
        if "spring" in joined or "whitelabel" in joined:
            return self._templates["framework_spring_boot_audit"]

        # 2. Cloud & Kubernetes
        if any(k8s in joined for k8s in ["kubernetes", "k8s", "etcd", "rancher", "docker", "minikube"]):
            return self._templates["cloud_kubernetes_metadata_audit"]
        if any(cld in joined for cld in ["aws", "azure", "gcp", "s3", "lambda", "blob.core.windows"]):
            return self._templates["cloud_serverless_lambda_audit"]

        # 3. Auth & Identity
        if any(auth_tech in joined for auth_tech in ["keycloak", "okta", "auth0", "oauth", "jwt", "saml"]):
            return self._templates["oauth_jwt_sso_audit"]

        # 4. DevOps & CI/CD Pipelines
        if any(ci in joined for ci in ["jenkins", "gitlab", "sonarqube", "artifactory", "teamcity", "nexus"]):
            return self._templates["cicd_devops_pipeline_audit"]

        # 5. Internal Admin Dashboards
        if any(adm in joined for adm in ["phpmyadmin", "grafana", "kibana", "portainer", "cpanel", "adminer"]):
            return self._templates["internal_admin_panel_audit"]

        # 6. API / Microservice
        if any(api_tech in joined for api_tech in ["fastapi", "express", "graphql", "swagger", "openapi", "apollo"]):
            return self._templates["api_microservice_audit"]
        if "grpc" in joined or "protobuf" in joined:
            return self._templates["microservice_grpc_protobuf_audit"]
        if "websocket" in joined or "socket.io" in joined or "ws://" in joined:
            return self._templates["websocket_realtime_audit"]
        if any(waf in joined for waf in ["cloudflare", "akamai", "imperva", "incapsula", "modsecurity"]):
            return self._templates["reverse_proxy_waf_bypass_audit"]

        # 7. Infrastructure / Ports exposure
        if open_ports:
            if len(open_ports) >= 3 or (22 in open_ports and any(p in {3306, 5432, 27017, 6379} for p in open_ports)):
                return self._templates["full_infrastructure_audit"]

            db_ports = {3306, 5432, 27017, 6379, 11211, 9200, 1433}
            if any(p in db_ports for p in open_ports):
                return self._templates["database_exposure_audit"]

            remote_ports = {22, 3389, 5900, 23}
            if any(p in remote_ports for p in open_ports) and not any(p in {80, 443, 8080} for p in open_ports):
                return self._templates["remote_management_rdp_ssh_audit"]

            mail_dns = {25, 53, 587}
            if any(p in mail_dns for p in open_ports) and not any(p in {80, 443} for p in open_ports):
                return self._templates["mail_dns_infrastructure_audit"]

        # Default fallback to OWASP Deep Web Audit
        return self._templates["web_owasp_deep_audit"]


template_registry = TemplateRegistry()
