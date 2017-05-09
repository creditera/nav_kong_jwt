-- Zuul JWT verifiecation module
-- Calls out to zuul in order to verify a users credentials

local http = require("socket.http")

local _M = {}
_M.__index = _M

function _M:verify(verification_host, token)
  body, code, headers = http.request {
    url = "http://" .. verification_host .. "/verifications",
    headers = {
      ["x-authentication-jwt"] = token
    }
  }

  print(code)
  if code == 204 then
    return true
  else
    return false
  end
end

return _M
