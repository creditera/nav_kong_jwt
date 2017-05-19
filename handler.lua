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

  -- Now use the verification module to verify the jwt on the upstream verification server
  if not jwt_verifier:verify(conf.verification_url, token) then
    error_body.code = "unauthorized"
    error_body.message = "Your token could not be verified. Please retrieve a new authentication token and try again."
    response_body.errors[1] = error_body

    return responses.send_HTTP_UNAUTHORIZED(response_body)
  end

  -- Decode token to find out who the consumer is
  local jwt, err = jwt_decoder:new(token)
  if err then
    error_body.code = "bad_token"
    error_body.message = "Bad token; "..tostring(err)
    response_body.errors[1] = error_body

    return responses.send_HTTP_UNAUTHORIZED(response_body)
  end

  local claims = jwt.claims

  local jwt_consumer_custom_id = claims[conf.consumer_custom_id_claim_name]
  if not jwt_consumer_custom_id then
    error_body.code = "missing_claims"
    error_body.message = "No mandatory '"..conf.consumer_custom_id_claim_name.."' in claims"
    response_body.errors[1] = error_body

    return responses.send_HTTP_UNAUTHORIZED(response_body)
  end

  local algorithm = "HS512"

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
  local consumer_key = "consumer_from_custom_id:" .. jwt_consumer_custom_id
  -- IMPORANT ONLY WORKS WITH KONG 0.9.x!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
  -- Version 0.10.x of Kong has a breaking change to the cache api.
  -- cache.get_or_set now takes a ttl argument between the key and callback.
  -- As a result, when we upgrade Kong to 0.10.x we need to also change the next
  -- line of code to:
  -- local consumer = cache.get_or_set(consumer_key, nil, function()
  local consumer = cache.get_or_set(consumer_key, function()
    local consumer_rows, err = singletons.dao.consumers:find_all {custom_id = jwt_consumer_custom_id}
    if #consumer_rows > 1 then
      error_body.code = "non_unique_consumer"
      error_body.message = "There are multiple consumers associated with your iss"
      response_body.errors[1] = error_body
      return responses.send_HTTP_INTERNAL_SERVER_ERROR(response_body)
    end

    if err then
      return responses.send_HTTP_INTERNAL_SERVER_ERROR(err)
    end

    local consumer = consumer_rows[1]
    return consumer
  end)

  -- However this should not happen
  if not consumer then
    error_body.code = "consumer_not_found"
    error_body.message = string_format("Could not find consumer for '%s'", conf.consumer_custom_id_claim_name)
    response_body.errors[1] = error_body

    return responses.send_HTTP_FORBIDDEN(response_body)
  end

  ngx.req.set_header(constants.HEADERS.CONSUMER_ID, consumer.id)
  ngx.req.set_header(constants.HEADERS.CONSUMER_CUSTOM_ID, consumer.custom_id)
  ngx.req.set_header("X-Account-ID", claims.sub)
  ngx.req.set_header("X-Actual-Sub", claims.actual_sub)
  ngx.req.set_header("X-Session-ID", claims.ses)
  ngx.req.set_header(constants.HEADERS.CONSUMER_USERNAME, consumer.username)
  ngx.ctx.authenticated_credential = consumer.id
  ngx.ctx.authenticated_consumer = consumer
end

return NavJwtHandler
