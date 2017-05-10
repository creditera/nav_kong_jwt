return {
  no_consumer = true,
  fields = {
    uri_param_names = {type = "array", default = {"jwt"}},
    consumer_username_claim_name = {type = "string", default = "iss"},
    secret_is_base64 = {type = "boolean", default = false},
    claims_to_verify = {type = "array", enum = {"exp", "nbf"}},
    verification_url = {type = "string", default = "http://zuul.service.consul/verifications"}
  }
}
