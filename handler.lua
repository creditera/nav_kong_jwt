local singletons = require "kong.singletons"
local BasePlugin = require "kong.plugins.base_plugin"
local cache = require "kong.tools.database_cache"
local responses = require "kong.tools.responses"
local constants = require "kong.constants"
local jwt_decoder = require "kong.plugins.nav_kong_jwt.jwt_parser"
local jwt_verifier = require "kong.plugins.nav_kong_jwt.jwt_verifier"
local string_format = string.format
local ngx_re_gmatch = ngx.re.gmatch

local NavJwtHandler = BasePlugin:extend()

NavJwtHandler.PRIORITY = 1000

--- Retrieve a JWT in a request.
-- Checks for the JWT in URI parameters, then in the `Authorization` header.
-- @param request ngx request object
-- @param conf Plugin configuration
-- @return token JWT token contained in request (can be a table) or nil
-- @return err
local function retrieve_token(request, conf)
  local uri_parameters = request.get_uri_args()

  for _, v in ipairs(conf.uri_param_names) do
    if uri_parameters[v] then
      return uri_parameters[v]
    end
  end

  local authorization_header = request.get_headers()["authorization"]
  if authorization_header then
    local iterator, iter_err = ngx_re_gmatch(authorization_header, "\\s*[Tt]oken\\s+(.+)")
    if not iterator then
      return nil, iter_err
    end

    local m, err = iterator()
    if err then
      return nil, err
    end

    if m and #m > 0 then
      return m[1]
    end
  end
end

function NavJwtHandler:new()
  NavJwtHandler.super.new(self, "nav_jwt")
end

function NavJwtHandler:access(conf)
  NavJwtHandler.super.access(self)
  response_body = {}
  response_body["errors"] = {}
  error_body = {}
  error_body.type = "authorization_error"

  local token, err = retrieve_token(ngx.req, conf)
  if err then
    error_body.code = "unspecified_error"
    error_body.message = "An unspecified error has occurred."..to_string(err)
    response_body.errors[1] = error_body

    return responses.send_HTTP_INTERNAL_SERVER_ERROR(response_body)
  end

  local ttype = type(token)
  if ttype ~= "string" then
    if ttype == "nil" then
      error_body.code = "no_credentials"
      error_body.message = "No credentials supplied. Please supply a JWT token in the Authorization header."
      response_body.errors[1] = error_body

      return responses.send_HTTP_UNAUTHORIZED(response_body)
    elseif ttype == "table" then
      error_body.code = "multiple_tokens_provided"
      error_body.message = "You've supplied multiple tokens in your request. Please limit your requests to provide a single authorization token."
      response_body.errors[1] = error_body

      return responses.send_HTTP_UNAUTHORIZED(response_body)
    else
      error_body.code = "unrecognizable_token"
      error_body.message = "You've supplied an unrecognizable token. Please reform your authorization token and try again."
      response_body.errors[1] = error_body

      return responses.send_HTTP_UNAUTHORIZED(response_body)
    end
  end

  -- Now verify the JWT signature
  if not jwt_verifier:verify(token) then
    error_body.code = "unauthorized"
    error_body.message = "Your token does not provide access to the system. Please generate a new token and try again."
    response_body.errors[1] = error_body

    return responses.send_HTTP_UNAUTHORIZED(response_body)
  end

  ngx.log(ngx.NOTICE, jwt_verifier:verify(token))
  -- Decode token to find out who the consumer is
  local jwt, err = jwt_decoder:new(token)
  if err then
    error_body.code = "bad_token"
    error_body.message = "Bad token; "..tostring(err)
    response_body.errors[1] = error_body

    return responses.send_HTTP_UNAUTHORIZED(response_body)
  end

  local claims = jwt.claims

  local jwt_secret_key = claims[conf.key_claim_name]
  if not jwt_secret_key then
    error_body.code = "missing_claims"
    error_body.message = "No mandatory '"..conf.key_claim_name.."' in claims"
    response_body.errors[1] = error_body

    return responses.send_HTTP_UNAUTHORIZED(response_body)
  end

  -- Retrieve the secret
  local jwt_secret = cache.get_or_set(cache.jwtauth_credential_key(jwt_secret_key),

   function()
    local rows, err = singletons.dao.jwt_secrets:find_all {key = jwt_secret_key}
    if err then
      return responses.send_HTTP_INTERNAL_SERVER_ERROR()
    elseif #rows > 0 then
      return rows[1]
    end
  end)

  if not jwt_secret then
    error_body.code = "missing_credentials"
    error_body.message = "No credentials found for given '"..conf.key_claim_name.."'"
    response_body.errors[1] = error_body

    return responses.send_HTTP_FORBIDDEN(response_body)
  end

  local algorithm = "HS512"

  -- Verify "alg"
  if jwt.header.alg ~= algorithm then
    error_body.code = "invalid_algorithm"
    error_body.message = "The algorithm you supplied is invalid; tokens must be formed with the HS512 algorithm."
    response_body.errors[1] = error_body

    return responses.send_HTTP_FORBIDDEN(response_body)
  end

  local jwt_secret_value = algorithm == "HS512" and jwt_secret.secret or jwt_secret.rsa_public_key
  if conf.secret_is_base64 then
    jwt_secret_value = jwt:b64_decode(jwt_secret_value)
  end

  if not jwt_secret_value then
    error_body.code = "invalid_key_or_secret"
    error_body.message = "The key or secret you provided was invalid."
    response_body.errors[1] = error_body

    return responses.send_HTTP_FORBIDDEN(response_body)
  end


  -- Verify the JWT registered claims
  local ok_claims, errors = jwt:verify_registered_claims(conf.claims_to_verify)
  if not ok_claims then
    i = 1
    for _, error_table in pairs(errors) do
      response_body["errors"][i] = error_table
      i = i + 1
    end

    return responses.send_HTTP_FORBIDDEN(response_body)
  end

  -- Retrieve the consumer
  local consumer = cache.get_or_set(cache.consumer_key(jwt_secret_key), function()
    local consumer, err = singletons.dao.consumers:find {id = jwt_secret.consumer_id}
    if err then
      return responses.send_HTTP_INTERNAL_SERVER_ERROR(err)
    end
    return consumer
  end)

  -- However this should not happen
  if not consumer then
    error_body.code = "consumer_not_found"
    error_body.message = string_format("Could not find consumer for '%s'", conf.key_claim_name)
    response_body.errors[1] = error_body

    return responses.send_HTTP_FORBIDDEN(response_body)
  end

  ngx.req.set_header(constants.HEADERS.CONSUMER_ID, consumer.id)
  ngx.req.set_header(constants.HEADERS.CONSUMER_CUSTOM_ID, consumer.custom_id)
  ngx.req.set_header("X-Account-ID", claims.sub)
  ngx.req.set_header("X-Actual-Sub", claims.actual_sub)
  ngx.req.set_header("X-Session-ID", claims.ses)
  ngx.req.set_header(constants.HEADERS.CONSUMER_USERNAME, consumer.username)
  ngx.ctx.authenticated_credential = jwt_secret
  ngx.ctx.authenticated_consumer = consumer
end

return NavJwtHandler
