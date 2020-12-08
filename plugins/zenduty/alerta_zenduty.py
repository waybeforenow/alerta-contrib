import json
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

    def _create_payload(self, alert):
        payload = {}

        payload["message"] = "%s: %s alert for %s with status %s" % (
            alert.environment,
            alert.severity.capitalize(),
            alert.resource,
            alert.event,
        )
        payload["alert_type"] = self._get_alert_type(alert)
        payload["entity_id"] = alert.id.replace("-", "")
        payload["payload"] = alert.serialize
        if alert.text:
            payload["summary"] = alert.text

        return payload

    def pre_receive(self, alert):
        return alert

    def status_change(self, alert, status, text, **kwargs):
        INTEGRATION_KEY = self.get_config("ZENDUTY_INTEGRATION_KEY", type=str, **kwargs)

        if status not in ["ack"]:
            return

        payload = self._create_payload(alert)
        payload["alert_type"] = "acknowledged"

        try:
            r = requests.post(
                "https://www.zenduty.com/api/events/{}/".format(INTEGRATION_KEY),
                headers={"Content-Type": "application/json"},
                data=json.dumps(payload, default=str),
            )
        except Exception as e:
            LOG.error("Error connecting to Zenduty: {}".format(e))

        LOG.debug("Zenduty response: %s\n%s" % (r.status_code, r.text))

    def post_receive(self, alert, **kwargs):
        INTEGRATION_KEY = self.get_config("ZENDUTY_INTEGRATION_KEY", type=str, **kwargs)

        if alert is None or alert.repeat:
            return

        payload = self._create_payload(alert)

        try:
            r = requests.post(
                "https://www.zenduty.com/api/events/{}/".format(INTEGRATION_KEY),
                headers={"Content-Type": "application/json"},
                data=json.dumps(payload, default=str),
            )
        except Exception as e:
            LOG.error("Error connecting to Zenduty: {}".format(e))

        LOG.debug("Zenduty response: %s\n%s" % (r.status_code, r.text))
