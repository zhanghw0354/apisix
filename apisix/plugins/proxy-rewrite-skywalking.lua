--
-- Licensed to the Apache Software Foundation (ASF) under one or more
-- contributor license agreements.  See the NOTICE file distributed with
-- this work for additional information regarding copyright ownership.
-- The ASF licenses this file to You under the Apache License, Version 2.0
-- (the "License"); you may not use this file except in compliance with
-- the License.  You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
--
local core        = require("apisix.core")
local plugin_name = "proxy-rewrite-skywalking"
local pairs       = pairs
local ipairs      = ipairs
local ngx         = ngx
local type        = type
local re_sub      = ngx.re.sub
local sub_str     = string.sub
local str_find    = core.string.find

local snowflake_inited = nil
local uuid = require("resty.jit-uuid")
local nanoid = require("nanoid")
local snowflake = require("snowflake")

local switch_map = {GET = ngx.HTTP_GET, POST = ngx.HTTP_POST, PUT = ngx.HTTP_PUT,
                    HEAD = ngx.HTTP_HEAD, DELETE = ngx.HTTP_DELETE,
                    OPTIONS = ngx.HTTP_OPTIONS, MKCOL = ngx.HTTP_MKCOL,
                    COPY = ngx.HTTP_COPY, MOVE = ngx.HTTP_MOVE,
                    PROPFIND = ngx.HTTP_PROPFIND, LOCK = ngx.HTTP_LOCK,
                    UNLOCK = ngx.HTTP_UNLOCK, PATCH = ngx.HTTP_PATCH,
                    TRACE = ngx.HTTP_TRACE,
}
local schema_method_enum = {}
for key in pairs(switch_map) do
    core.table.insert(schema_method_enum, key)
end

local lrucache = core.lrucache.new({
    type = "plugin",
})

local schema = {
    type = "object",
    properties = {
        uri = {
            description = "new uri for upstream",
            type        = "string",
            minLength   = 1,
            maxLength   = 4096,
            pattern     = [[^\/.*]],
        },
        method = {
            description = "proxy route method",
            type        = "string",
            enum        = schema_method_enum
        },
        regex_uri = {
            description = "new uri that substitute from client uri " ..
                    "for upstream, lower priority than uri property",
            type        = "array",
            maxItems    = 2,
            minItems    = 2,
            items       = {
                description = "regex uri",
                type = "string",
            }
        },
        host = {
            description = "new host for upstream",
            type        = "string",
            pattern     = [[^[0-9a-zA-Z-.]+(:\d{1,5})?$]],
        },
        headers = {
            description = "new headers for request",
            oneOf = {
                {
                    type = "object",
                    minProperties = 1,
                    additionalProperties = false,
                    properties = {
                        add = {
                            type = "object",
                            minProperties = 1,
                            patternProperties = {
                                ["^[^:]+$"] = {
                                    oneOf = {
                                        { type = "string" },
                                        { type = "number" }
                                    }
                                }
                            },
                        },
                        set = {
                            type = "object",
                            minProperties = 1,
                            patternProperties = {
                                ["^[^:]+$"] = {
                                    oneOf = {
                                        { type = "string" },
                                        { type = "number" },
                                    }
                                }
                            },
                        },
                        remove = {
                            type = "array",
                            minItems = 1,
                            items = {
                                type = "string",
                                -- "Referer"
                                pattern = "^[^:]+$"
                            }
                        },
                    },
                },
                {
                    type = "object",
                    minProperties = 1,
                    patternProperties = {
                        ["^[^:]+$"] = {
                            oneOf = {
                                { type = "string" },
                                { type = "number" }
                            }
                        }
                    },
                }
            },

        },
        use_real_request_uri_unsafe = {
            description = "use real_request_uri instead, THIS IS VERY UNSAFE.",
            type        = "boolean",
            default     = false,
        },
    },
    minProperties = 1,
}


local _M = {
    version  = 0.1,
    priority = 1008,
    name     = plugin_name,
    schema   = schema,
}

local function is_new_headers_conf(headers)
    return (headers.add and type(headers.add) == "table") or
            (headers.set and type(headers.set) == "table") or
            (headers.remove and type(headers.remove) == "table")
end

local function check_set_headers(headers)
    for field, value in pairs(headers) do
        if type(field) ~= 'string' then
            return false, 'invalid type as header field'
        end

        if type(value) ~= 'string' and type(value) ~= 'number' then
            return false, 'invalid type as header value'
        end

        if #field == 0 then
            return false, 'invalid field length in header'
        end

        core.log.info("header field: ", field)
        if not core.utils.validate_header_field(field) then
            return false, 'invalid field character in header'
        end
        if not core.utils.validate_header_value(value) then
            return false, 'invalid value character in header'
        end
    end

    return true
end

function dec(data)
    local b='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    data = string.gsub(data, '[^'..b..'=]', '')
    return (data:gsub('.', function(x)
        if (x == '=') then return '' end
        local r,f='',(b:find(x)-1)
        for i=6,1,-1 do r=r..(f%2^i-f%2^(i-1)>0 and '1' or '0') end
        return r;
    end):gsub('%d%d%d?%d?%d?%d?%d?%d?', function(x)
        if (#x ~= 8) then return '' end
        local c=0
        for i=1,8 do c=c+(x:sub(i,i)=='1' and 2^(8-i) or 0) end
        return string.char(c)
    end))
end

function split(str,reps)
    local resultStrList = {}
    string.gsub(str,'[^'..reps..']+',function (w)
        table.insert(resultStrList,w)
    end)
    return resultStrList
end

local function get_request_id(algorithm)
    if algorithm == "uuid" then
        return uuid()
    end
    if algorithm == "nanoid" then
        return nanoid.safe_simple()
    end
    return next_id()
end

local function next_id()
    if snowflake_inited == nil then
        snowflake_init()
    end
    return snowflake:next_id()
end


local function snowflake_init()
    if snowflake_inited == nil then
        local max_number = math_pow(2, (attr.snowflake.data_machine_bits))
        local datacenter_id_bits = math_floor(attr.snowflake.data_machine_bits / 2)
        local node_id_bits = math_ceil(attr.snowflake.data_machine_bits / 2)
        data_machine = gen_data_machine(max_number)
        if data_machine == nil then
            return ""
        end

        local worker_id, datacenter_id = split_data_machine(data_machine,
                node_id_bits, datacenter_id_bits)

        core.log.info("snowflake init datacenter_id: " ..
                datacenter_id .. " worker_id: " .. worker_id)
        snowflake.init(
                datacenter_id,
                worker_id,
                attr.snowflake.snowflake_epoc,
                node_id_bits,
                datacenter_id_bits,
                attr.snowflake.sequence_bits,
                attr.delta_offset
        )
        snowflake_inited = true
    end
end

function _M.check_schema(conf)
    local ok, err = core.schema.check(schema, conf)
    if not ok then
        return false, err
    end

    if conf.regex_uri and #conf.regex_uri > 0 then
        local _, _, err = re_sub("/fake_uri", conf.regex_uri[1],
                conf.regex_uri[2], "jo")
        if err then
            return false, "invalid regex_uri(" .. conf.regex_uri[1] ..
                    ", " .. conf.regex_uri[2] .. "): " .. err
        end
    end

    -- check headers
    if not conf.headers then
        return true
    end

    if conf.headers then
        if not is_new_headers_conf(conf.headers) then
            ok, err = check_set_headers(conf.headers)
            if not ok then
                return false, err
            end
        end
    end

    return true
end


do
    local upstream_vars = {
        host       = "upstream_host",
        upgrade    = "upstream_upgrade",
        connection = "upstream_connection",
    }
    local upstream_names = {}
    for name, _ in pairs(upstream_vars) do
        core.table.insert(upstream_names, name)
    end

    local function create_header_operation(hdr_conf)
        local set = {}
        local add = {}

        if is_new_headers_conf(hdr_conf) then
            if hdr_conf.add then
                for field, value in pairs(hdr_conf.add) do
                    core.table.insert_tail(add, field, value)
                end
            end
            if hdr_conf.set then
                for field, value in pairs(hdr_conf.set) do
                    core.table.insert_tail(set, field, value)
                end
            end

        else
            for field, value in pairs(hdr_conf) do
                core.table.insert_tail(set, field, value)
            end
        end

        return {
            add = add,
            set = set,
            remove = hdr_conf.remove or {},
        }
    end


    function _M.rewrite(conf, ctx)
        for _, name in ipairs(upstream_names) do
            if conf[name] then
                ctx.var[upstream_vars[name]] = conf[name]
            end
        end

        local upstream_uri = ctx.var.uri
        if conf.use_real_request_uri_unsafe then
            upstream_uri = ctx.var.real_request_uri
        elseif conf.uri ~= nil then
            upstream_uri = core.utils.resolve_var(conf.uri, ctx.var)
        elseif conf.regex_uri ~= nil then
            local uri, _, err = re_sub(ctx.var.uri, conf.regex_uri[1],
                    conf.regex_uri[2], "jo")
            if uri then
                upstream_uri = uri
            else
                local msg = "failed to substitute the uri " .. ctx.var.uri ..
                        " (" .. conf.regex_uri[1] .. ") with " ..
                        conf.regex_uri[2] .. " : " .. err
                core.log.error(msg)
                return 500, {message = msg}
            end
        end

        if not conf.use_real_request_uri_unsafe then
            local index = str_find(upstream_uri, "?")
            if index then
                upstream_uri = core.utils.uri_safe_encode(sub_str(upstream_uri, 1, index-1)) ..
                        sub_str(upstream_uri, index)
            else
                upstream_uri = core.utils.uri_safe_encode(upstream_uri)
            end

            if ctx.var.is_args == "?" then
                if index then
                    ctx.var.upstream_uri = upstream_uri .. "&" .. (ctx.var.args or "")
                else
                    ctx.var.upstream_uri = upstream_uri .. "?" .. (ctx.var.args or "")
                end
            else
                ctx.var.upstream_uri = upstream_uri
            end
        end

        if conf.headers then
            local hdr_op, err = core.lrucache.plugin_ctx(lrucache, ctx, nil,
                    create_header_operation, conf.headers)
            if not hdr_op then
                core.log.error("failed to create header operation: ", err)
                return
            end

            local field_cnt = #hdr_op.add
            for i = 1, field_cnt, 2 do
                local val = core.utils.resolve_var(hdr_op.add[i + 1], ctx.var)
                local header = hdr_op.add[i]
                core.request.add_header(header, val)
            end

            local field_cnt = #hdr_op.set
            for i = 1, field_cnt, 2 do
                local list = split(core.request.header(ctx,"sw8"),"-")
                local val = core.utils.resolve_var(hdr_op.set[i + 1], ctx.var)
                if hdr_op.set[i]== "x-yun-tid" and #list==8 then
                    local res,info = pcall(dec,list[2])
                    if res then
                        val = info
                        core.log.error("failed to create header operation 1: ", val)
                    else
                        val = get_request_id("uuid")
                        core.log.error("failed to create header operation 2: ", val)
                    end
                else
                    val = get_request_id("uuid")
                    core.log.error("failed to create header operation 3: ", val)
                end
                core.request.set_header(hdr_op.set[i], val)
            end

            local field_cnt = #hdr_op.remove
            for i = 1, field_cnt do
                core.request.set_header(hdr_op.remove[i], nil)
            end

        end

        if conf.method then
            ngx.req.set_method(switch_map[conf.method])
        end
    end

end  -- do


return _M
