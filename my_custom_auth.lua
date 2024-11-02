local jwt_decoder = require "kong.plugins.jwt.jwt_parser"

-- Define the plugin
local MyCustomAuthPlugin = {
  PRIORITY = 1000,
  VERSION = "1.0",
}

function MyCustomAuthPlugin:access(config)
  MyCustomAuthPlugin.super.access(self)

  -- Extract `projectID` from the request URL (assuming the format `/projects/{projectID}/...`)
  local request_path = kong.request.get_path()
  local project_id = string.match(request_path, "/projects/(%w+)")

  -- Get the JWT token from the Authorization header
  local auth_header = kong.request.get_header("Authorization")
  if not auth_header then
    return kong.response.exit(401, { message = "Missing Authorization token" })
  end

  -- Parse the JWT token to extract claims
  local token = string.gsub(auth_header, "Bearer%s+", "")
  local decoded_jwt, err = jwt_decoder:new(token)
  if err then
    return kong.response.exit(401, { message = "Invalid token" })
  end

  -- Extract role and projectID from the JWT claims
  local claims = decoded_jwt.claims
  local jwt_project_id = claims["projectID"]
  local user_role = claims["role"]

  -- Authorization Logic
  if jwt_project_id ~= project_id then
    return kong.response.exit(403, { message = "Unauthorized project access" })
  end

  if user_role ~= "admin" then
    return kong.response.exit(403, { message = "Access forbidden: Insufficient role" })
  end

  -- If all checks pass, allow the request to continue
end

return MyCustomAuthPlugin
