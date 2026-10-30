"""RTL-aware Swagger UI for Persian documentation.

Keeps the real, generated OpenAPI document (``/openapi.json``) untouched and
serves a custom HTML shell at ``/api/docs`` (URL unchanged) with:

- ``dir="rtl"`` page direction and right-aligned Persian prose.
- Selective ``dir="ltr"`` for technical content: JSON bodies, code blocks,
  HTTP methods, URL paths, parameter names, inputs, and numeric values.
- Unmodified Try-it-out behavior (we only style the DOM; SwaggerUIBundle is
  initialized with the same parameters FastAPI uses).

The DOM fixes are applied twice: once via CSS for known Swagger-UI classes
and once via a MutationObserver in a few lines of vanilla JS for dynamically
rendered nodes. No frontend framework, no separate build step.
"""

from __future__ import annotations

from typing import Any


def rtl_swagger_ui_html(*, openapi_url: str, title: str) -> str:
    swagger_css = "https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css"
    swagger_bundle_js = "https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"
    swagger_preset_js = "https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-standalone-preset.js"
    return f"""<!DOCTYPE html>
<html dir="rtl" lang="fa">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<link rel="stylesheet" href="{swagger_css}">
<style>
  /* ---- RTL shell -------------------------------------------------------- */
  html, body {{ direction: rtl; }}
  body {{
    font-family: Vazirmatn, "Vazir", Tahoma, "Segoe UI", sans-serif;
    text-align: right;
    margin: 0; padding: 0;
  }}
  #swagger-ui .information-container, #swagger-ui .scheme-container,
  #swagger-ui .wrapper {{ direction: rtl; text-align: right; }}
  #swagger-ui .info .title, #swagger-ui .info .main, #swagger-ui .info p,
  #swagger-ui .info li, #swagger-ui .info .base-url,
  #swagger-ui .opblock-description-wrapper p,
  #swagger-ui .opblock-external-docs-wrapper,
  #swagger-ui .opblock-summary-description,
  #swagger-ui .responses-inner h4, #swagger-ui .responses-inner h5,
  #swagger-ui .parameter__name, #swagger-ui .parameter__type,
  #swagger-ui .parameter__description, #swagger-ui .response-col_description,
  #swagger-ui .response-col_description .markdown,
  #swagger-ui .models h2, #swagger-ui .model-box,
  #swagger-ui .tag-description, #swagger-ui .swagger-ui .markdown p,
  #swagger-ui .tab li, #swagger-ui .btn-group .btn-label,
  #swagger-ui .dialog-ux .modal-ux-content p,
  #swagger-ui .auth-wrapper .auth-btn {{ direction: rtl; text-align: right; }}
  #swagger-ui .info .title {{ text-align: right; }}
  #swagger-ui .tag {{ direction: rtl; }}
  #swagger-ui .opblock-tag {{ direction: rtl; text-align: right; }}

  /* ---- LTR islands: JSON, code, paths, inputs ---------------------------- */
  #swagger-ui pre,
  #swagger-ui code,
  #swagger-ui .microlight,
  #swagger-ui .highlight-code,
  #swagger-ui .language-json,
  #swagger-ui .opblock-summary-path,
  #swagger-ui .opblock-summary-path__deprecated,
  #swagger-ui .opblock-summary-control .path,
  #swagger-ui .responses-table .response-col_links,
  #swagger-ui .model {{ direction: ltr; text-align: left; }}
  #swagger-ui .opblock-summary-method {{ direction: ltr; }}
  #swagger-ui input[type="text"], #swagger-ui input[type="password"],
  #swagger-ui input[type="number"], #swagger-ui input[type="email"],
  #swagger-ui textarea, #swagger-ui select {{
    direction: ltr; text-align: left; unicode-bidi: plaintext;
  }}
  #swagger-ui .parameter__name {{ direction: ltr; unicode-bidi: plaintext; }}
  #swagger-ui .parameter__name small {{ direction: rtl; }}
  #swagger-ui .parameter__in {{ direction: ltr; }}
  #swagger-ui .tab li .tabitem {{ direction: rtl; }}

  /* ---- polish ------------------------------------------------------------ */
  #swagger-ui .info .title small {{ direction: ltr; }}
  #swagger-ui .scheme-container {{ box-shadow: none; }}
  #swagger-ui .opblock .opblock-section-header {{ direction: rtl; }}
  #swagger-ui .opblock .opblock-section-header h4 {{ direction: rtl; text-align: right; }}
  #swagger-ui .try-out__btn, #swagger-ui .execute, #swagger-ui .btn.execute {{ direction: rtl; }}
</style>
</head>
<body>
<div id="swagger-ui"></div>
<script src="{swagger_bundle_js}" crossorigin></script>
<script src="{swagger_preset_js}" crossorigin></script>
<script>
window.onload = function () {{
  var ui = SwaggerUIBundle({{
    url: "{openapi_url}",
    dom_id: "#swagger-ui",
    deepLinking: true,
    showExtensions: true,
    showCommonExtensions: true,
    presets: [SwaggerUIBundle.presets.apis, SwaggerUIStandalonePreset],
    layout: "StandaloneLayout",
  }});
  window.ui = ui;

  /* Keep technical content LTR even when re-rendered dynamically. */
  var LTR_SELECTOR = [
    "pre", "code", ".microlight", ".highlight-code", ".language-json",
    ".opblock-summary-path", ".opblock-summary-path__deprecated",
    ".model", "input", "textarea"
  ].join(",");
  function fixDirection(root) {{
    if (!root.querySelectorAll) return;
    root.querySelectorAll(LTR_SELECTOR).forEach(function (el) {{
      el.setAttribute("dir", "ltr");
    }});
  }}
  fixDirection(document.getElementById("swagger-ui"));
  var observer = new MutationObserver(function (mutations) {{
    mutations.forEach(function (m) {{
      m.addedNodes.forEach(function (node) {{
        if (node.nodeType === 1) fixDirection(node);
      }});
    }});
  }});
  observer.observe(document.getElementById("swagger-ui"),
                    {{ childList: true, subtree: true }});
}};
</script>
</body>
</html>"""
