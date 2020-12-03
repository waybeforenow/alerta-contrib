import logging
import requests


try:
    from alerta.plugins import app  # alerta >= 5.0
except ImportError:
    from alerta.app import app  # alerta < 5.0
from alerta.plugins import PluginBase

LOG = logging.getLogger("alerta.plugins.zenduty")


class ServiceIntegration(PluginBase):
    def _get_alert_type(self, alert):
        ret = "info"
        if alert.severity in ["security", "critical"]:
            ret = "critical"
        elif alert.severity in ["major"]:
            ret = "error"
        elif alert.severity in ["minor", "warning"]:
            ret = "warning"

        if alert.status in ["ack"]:
            ret = "acknowledged"
        elif alert.status in ["closed", "expired"]:
            ret = "resolved"

        return ret

    def pre_receive(self, alert):
        return alert

    def status_change(self, alert, status, text, **kwargs):
        INTEGRATION_KEY = self.get_config("ZENDUTY_INTEGRATION_KEY", type=str, **kwargs)

        if status not in ["ack", "assign"]:
            return

        payload = {}

        payload["message"] = "%s: %s alert for %s - %s is %s" % (
            alert.environment,
            alert.severity.capitalize(),
            ",".join(alert.service),
            alert.resource,
            alert.event,
        )
        payload["alert_type"] = "acknowledged"
        payload["entity_id"] = alert.id
        payload["payload"] = alert.serialize

        LOG.debug(
            requests.post(
                "https://www.zenduty.com/api/events/{}/".format(INTEGRATION_KEY),
                json=payload,
            )
        )

    def post_receive(self, alert, **kwargs):
        INTEGRATION_KEY = self.get_config("ZENDUTY_INTEGRATION_KEY", type=str, **kwargs)

        if alert.repeat:
            return

        payload = {}

        payload["message"] = "%s: %s alert for %s - %s is %s" % (
            alert.environment,
            alert.severity.capitalize(),
            ",".join(alert.service),
            alert.resource,
            alert.event,
        )
        payload["alert_type"] = self._get_alert_type(alert)
        payload["entity_id"] = alert.id
        payload["payload"] = alert.serialize

        LOG.debug(
            requests.post(
                "https://www.zenduty.com/api/events/{}/".format(INTEGRATION_KEY),
                json=payload,
            )
        )
