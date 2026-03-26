import { defineCheckV2, Severity } from "engine";

import { Tags } from "../../types";
import { keyStrategy } from "../../utils/key";

const DJANGO_DEBUG_SIGNATURES = [
  "You're seeing this error because you have <code>DEBUG = True</code>",
  "DisallowedHost at",
];

const DJANGO_ADDITIONAL_SIGNATURES = [
  "django.core.exceptions",
  "DJANGO_SETTINGS_MODULE",
  "django.utils.datastructures.MultiValueDictKeyError",
  "django.template.exceptions.TemplateDoesNotExist",
];

function hasDjangoDebugSignature(body: string): boolean {
  for (const sig of DJANGO_DEBUG_SIGNATURES) {
    if (body.includes(sig)) {
      return true;
    }
  }
  for (const sig of DJANGO_ADDITIONAL_SIGNATURES) {
    if (body.includes(sig)) {
      return true;
    }
  }
  return false;
}

export default defineCheckV2({
  id: "django-debug",
  name: "Django Debug Mode Enabled",
  description:
    "Detects Django applications running with DEBUG=True, which exposes detailed error pages, settings, and SQL queries",
  type: "passive",
  tags: [Tags.FRAMEWORK, Tags.DEBUG],
  severities: [Severity.MEDIUM],
  aggressivity: {
    minRequests: 0,
    maxRequests: 0,
  },
  dedupeKey: keyStrategy().withHost().withPort().build(),
  when: (target) => {
    if (target.response === undefined) return false;
    return target.response.getCode() >= 400;
  },

  execute(ctx) {
    const body = ctx.target.bodyText();
    if (body === undefined) return Promise.resolve();

    if (!hasDjangoDebugSignature(body)) return Promise.resolve();

    ctx.finding({
      name: "Django Debug Mode Enabled",
      description:
        "The application is running with Django's `DEBUG = True` setting. Error pages expose detailed information including:\n\n- Full Python tracebacks with local variables\n- Django settings (including potential secrets)\n- SQL queries with parameters\n- Request/response details\n- Installed middleware and URL patterns",
      severity: Severity.MEDIUM,
      impact:
        "Attackers can extract sensitive configuration data, database credentials, secret keys, and application structure from Django debug error pages.",
      recommendation:
        "Set `DEBUG = False` in production settings. Configure proper error handling with custom 404 and 500 error pages. Use environment variables to manage the DEBUG setting across environments.",
    });

    return Promise.resolve();
  },
});
