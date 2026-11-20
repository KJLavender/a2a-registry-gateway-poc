"""What Keycloak 26.8 token-exchange delegation (preview) does in a multi-hop agent chain.

Runs only against the Keycloak from keycloak/docker-compose.yml (POC_IDP=keycloak):
    POC_IDP=keycloak python -m unittest tests.test_keycloak_delegation -v

Findings encoded here:
  - With the user's consent, agent-gateway can exchange the user's token for one that carries
    `act: {client_id: agent-gateway}`, for any audience it is configured for.
  - Only the holder of the user's original token (the one with `may_act`) can do that. A token that
    carries `act` or `may_act` cannot be exchanged again, by standard exchange or by delegation, so
    `act` names one actor and cannot grow into a chain (gateway > registry > gateway > agent).
  - A user token with `may_act` is refused by standard exchange, so delegation and the PoC's
    origin-scope approach cannot be used on the same token.
"""
from __future__ import annotations

import unittest

from poc import keycloak_delegation as kd
from poc.common.jwt import unverified_claims
from poc.common.web import http
from poc.settings import Settings

SETTINGS = Settings()
SCOPE = f"openid delegation:client:{kd.ACTOR}"


def setUpModule() -> None:
    if SETTINGS.idp_impl != "keycloak":
        raise unittest.SkipTest("set POC_IDP=keycloak and start keycloak/docker-compose.yml")
    try:
        status = http("GET", f"{SETTINGS.issuer}/.well-known/openid-configuration", timeout=3)[0]
    except OSError:
        status = 0
    if status != 200:
        raise unittest.SkipTest("Keycloak is not running")
    kd.ensure_delegation_permission(SETTINGS)


class KeycloakDelegation(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.user_token = kd.browser_login(SETTINGS, "alice", SCOPE)["access_token"]
        cls.gateway_actor = kd.service_token(SETTINGS, "agent-gateway")
        cls.registry_actor = kd.service_token(SETTINGS, "agent-registry")

    def delegated(self, audience: str) -> str:
        status, body = kd.exchange(SETTINGS, "agent-gateway", self.user_token, audience, self.gateway_actor)
        self.assertEqual(status, 200, body)
        return body["access_token"]

    def test_consent_puts_may_act_in_the_user_token(self):
        claims = unverified_claims(self.user_token)
        self.assertEqual(claims["may_act"]["client_id"], "agent-gateway")
        self.assertIn("agent-gateway", claims["aud"] if isinstance(claims["aud"], list) else [claims["aud"]])

    def test_delegated_exchange_adds_act(self):
        for audience in ("agent-registry", "agent:report-analyst"):
            claims = unverified_claims(self.delegated(audience))
            self.assertEqual(claims["preferred_username"], "alice")
            self.assertEqual(claims["aud"], audience)
            self.assertEqual(claims["act"]["client_id"], "agent-gateway")
            self.assertNotIn("may_act", claims)
            self.assertIn("dept-analytics", claims["groups"])  # claims come from the actor's client scopes

    def test_other_client_cannot_use_the_consent(self):
        status, body = kd.exchange(SETTINGS, "agent-registry", self.user_token, "agent-gateway", self.registry_actor)
        self.assertEqual(status, 400)
        self.assertIn("may_act", body["error_description"])

    def test_act_token_cannot_be_exchanged_again(self):
        hop1 = self.delegated("agent-registry")
        standard = kd.exchange(SETTINGS, "agent-registry", hop1, "agent-gateway")
        redelegated = kd.exchange(SETTINGS, "agent-registry", hop1, "agent-gateway", self.registry_actor)
        self.assertEqual(standard[0], 400)
        self.assertEqual(redelegated[0], 400)

    def test_standard_exchange_refuses_a_consented_user_token(self):
        status, body = kd.exchange(SETTINGS, "agent-gateway", self.user_token, "agent-registry")
        self.assertEqual(status, 400)
        self.assertIn("delegation claim", body["error_description"])

    def test_no_permission_means_no_may_act(self):
        # agent-registry has no FGAP delegate permission: the scope is dropped, login still succeeds
        token = kd.browser_login(SETTINGS, "bob", "openid delegation:client:agent-registry")["access_token"]
        self.assertNotIn("may_act", unverified_claims(token))


if __name__ == "__main__":
    unittest.main()
