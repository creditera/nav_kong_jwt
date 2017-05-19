-- Zuul JWT verification module
-- Calls out to an upstream zuul in order to verify a user's jwt and session

local http = require("socket.http")

local _M = {}
_M.__index = _M

function _M:verify(verification_url, token)
  body, code, headers = http.request {
    url = verification_url,
    headers = {
      ["x-authentication-jwt"] = token
    }
  }

  if code == 204 then
    return true
  else
    return false
  end
end

return _M
