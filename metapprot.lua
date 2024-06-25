-- Meterpreter protocol dessector for WireShark
-- https://github.com/rapid7/meterpreter
--
-- Copyright (c) I.Medvedkov (iLya2IK) 2024

local openssl = require('openssl')
local pkey = require('openssl').pkey
local cipher = require'openssl'.cipher
local base64 = require'base64'

_G.debug = require("debug")

-- create myproto protocol and its fields
local m_proto_name = "metasPROT"
p_myproto = Proto (m_proto_name,"Meterpreter packet")
local f_xor_seg = ProtoField.uint32("metapPROT.xor_seg", "XOR segment", base.HEX)
local f_packet_head = ProtoField.none("metapPROT.packet_head", "Packet header")
local f_expr = ProtoField.none("metapPROT.expression", "Expression")
local f_packet_payload = ProtoField.none("metapPROT.packet_payload", "Packet payload")
local f_payload_irs = ProtoField.bytes("metapPROT.irs", "Initial vector", base.COLON)
local f_guid = ProtoField.bytes("metapPROT.guid", "GUID", base.COLON)
local f_enc = ProtoField.uint32("metapPROT.enc", "Encrypt", base.DEC)
local f_length = ProtoField.uint32("metapPROT.length", "Length", base.DEC)
local f_type = ProtoField.uint32("metapPROT.type", "Type", base.HEX)
local f_data = ProtoField.bytes("metapPROT.data", "Data", base.COLON)
local f_payload_str = ProtoField.stringz("metapPROT.pl_string", "String", FT_STRING)
local f_payload_raw = ProtoField.bytes("metapPROT.pl_raw", "Raw", base.COLON)
local f_payload_uint32 = ProtoField.uint32("metapPROT.pl_u32", "UInt32", base.DEC)
local f_payload_uint64 = ProtoField.uint64("metapPROT.pl_u64", "UInt64", base.DEC)
local f_payload_int8 = ProtoField.int8("metapPROT.pl_8", "Int8", base.DEC)
p_myproto.fields = {f_xor_seg, f_packet_head, f_expr, f_packet_payload, f_payload_irs, f_guid, f_enc, f_length, f_type, f_payload_str, f_payload_raw, f_payload_uint32, f_payload_uint64, f_payload_int8, f_data}

local commands = {}
local comm_len = 0
local metas = {}
local types = {}

local TLV_META_TYPE_NONE       = 0
local TLV_META_TYPE_STRING     = 0x00010000
local TLV_META_TYPE_UINT       = 0x00020000
local TLV_META_TYPE_RAW        = 0x00040000
local TLV_META_TYPE_BOOL       = 0x00080000
local TLV_META_TYPE_QWORD      = 0x00100000
local TLV_META_TYPE_COMPRESSED = 0x20000000
local TLV_META_TYPE_GROUP      = 0x40000000
local TLV_META_TYPE_COMPLEX    = 0x80000000

local TLV_TYPE_COMMAND_ID  = 1
local TLV_TYPE_RSA_PUB_KEY = 550
local TLV_TYPE_ENC_SYM_KEY = 553

COMMAND_ID_CORE_CHANNEL_CLOSE            = 1
COMMAND_ID_CORE_CHANNEL_EOF              = 2
COMMAND_ID_CORE_CHANNEL_INTERACT         = 3
COMMAND_ID_CORE_CHANNEL_OPEN             = 4
COMMAND_ID_CORE_CHANNEL_READ             = 5
COMMAND_ID_CORE_CHANNEL_SEEK             = 6
COMMAND_ID_CORE_CHANNEL_TELL             = 7
COMMAND_ID_CORE_CHANNEL_WRITE            = 8
COMMAND_ID_CORE_CONSOLE_WRITE            = 9
COMMAND_ID_CORE_ENUMEXTCMD               = 10
COMMAND_ID_CORE_GET_SESSION_GUID         = 11
COMMAND_ID_CORE_LOADLIB                  = 12
COMMAND_ID_CORE_MACHINE_ID               = 13
COMMAND_ID_CORE_MIGRATE                  = 14
COMMAND_ID_CORE_NATIVE_ARCH              = 15
COMMAND_ID_CORE_NEGOTIATE_TLV_ENCRYPTION = 16
COMMAND_ID_CORE_PATCH_URL                = 17
COMMAND_ID_CORE_PIVOT_ADD                = 18
COMMAND_ID_CORE_PIVOT_REMOVE             = 19
COMMAND_ID_CORE_PIVOT_SESSION_DIED       = 20
COMMAND_ID_CORE_SET_SESSION_GUID         = 21
COMMAND_ID_CORE_SET_UUID                 = 22
COMMAND_ID_CORE_SHUTDOWN                 = 23
COMMAND_ID_CORE_TRANSPORT_ADD            = 24
COMMAND_ID_CORE_TRANSPORT_CHANGE         = 25
COMMAND_ID_CORE_TRANSPORT_GETCERTHASH    = 26
COMMAND_ID_CORE_TRANSPORT_LIST           = 27
COMMAND_ID_CORE_TRANSPORT_NEXT           = 28
COMMAND_ID_CORE_TRANSPORT_PREV           = 29
COMMAND_ID_CORE_TRANSPORT_REMOVE         = 30
COMMAND_ID_CORE_TRANSPORT_SETCERTHASH    = 31
COMMAND_ID_CORE_TRANSPORT_SET_TIMEOUTS   = 32
COMMAND_ID_CORE_TRANSPORT_SLEEP          = 33

local RSA_PUB_KEY
local RSA_PRIVATE_KEY = nil
local RSA_PRIVATE_KEYS = {}

UNKNOWN    = "Unknown"

ENC_AES256_CBC = "AES_256_CBC"

TYPE_REQUEST  = "Request"
TYPE_RESPONSE = "Response"
TYPE_PLAIN_REQUEST  = "Plain Request"
TYPE_PLAIN_RESPONSE = "Plain Response"

DATA_PUBK = "Public key"
DATA_PRVK = "Private key"
DATA_DECODED_HEADER = 'Decoded header'
DATA_DECODED_PAYLOAD = 'Decoded payload'
DATA_DECRYPTED = 'Decrypted'

MSG_PUBK_FOUND = "Public key found"
MSG_PRVK_FOUND = "Private key found"
ERR_PUBK_WRONG = "Wrong public key found"
ERR_UNKNOWN_TYPE = "Unknown packet type"
ERR_ECRYPTED = "Encrypted packet detected, but no key found"

local default_settings =
{
    keys  = "",
    tcp_port = 4444,
}

function addmeta(label, value)
    metas = {
        name = label,
        kind = 0,
        meta = value,
    }
    table.insert(metas, v)
end

function addtype(metat, label, value)
    v = {
        name = label,
        kind = value,
        meta = metat,
    }
    table.insert(types, v)
end

function addcomm(index, label)
    commands[index] = label
end

local function hexdecode(hex)
   return (hex:gsub("%x%x", function(digits) return string.char(tonumber(digits, 16)) end))
end

local function hexencode(str)
   return (str:gsub(".", function(char) return string.format("%02x", char:byte()) end))
end

function split_keys(inputstr, sep)
  if sep == nil then
    sep = "%s"
  end
  local t = {}
  for str in string.gmatch(inputstr, "([^"..sep.."]+)") do
    table.insert(t, str)
    print("found:".. str)
  end
  return t
end

function split_meth_key(inputstr)
  f, v, s = string.match(inputstr, "^([^:]+):(%x+)$")
  if (v ~= nil) and (v ~= '') and (f ~= nil) then
    print("m:".. f .." k:".. v)
    local t = {}
    t.meth = f
    t.key = hexdecode(v)
    return t
  else
    return nil
  end
end

local function splitByChunk(text, chunkSize)
    local s = ""
    for i=1, #text, chunkSize do
        s = s.. text:sub(i,i+chunkSize - 1).. '\n'
    end
    return s
end

function der_to_pem(der_data)
   pem = "-----BEGIN PUBLIC KEY-----\n".. splitByChunk(der_data, 64) .."-----END PUBLIC KEY-----\n"
   return pem;
end

function try_to_decrypt(seq, irs)
    if RSA_PRIVATE_KEY ~= nil then
        res = cipher.cipher(RSA_PRIVATE_KEY.meth, false, seq, RSA_PRIVATE_KEY.key, irs)
        if res ~= nil then
            return res
        end
    end

    for _, value in ipairs(RSA_PRIVATE_KEYS) do
        res = cipher.cipher(value.meth, false, seq, value.key, irs)
        if res ~= nil then
            RSA_PRIVATE_KEY = value
            return res
        end
    end

    return nil
end


function initdata()
    local splitted = split_keys(default_settings.keys, ";")

    RSA_PRIVATE_KEY = nil
    local cnt = 1
    for i, value in ipairs(splitted) do
        local t = split_meth_key(value)
        if t ~= nil then
            RSA_PRIVATE_KEYS[cnt] = t
            cnt = cnt + 1
        end
    end

    addmeta("TLV_META_TYPE_NONE",      0)
    addmeta("TLV_META_TYPE_STRING",    TLV_META_TYPE_STRING)
    addmeta("TLV_META_TYPE_UINT",      TLV_META_TYPE_UINT)
    addmeta("TLV_META_TYPE_RAW",       TLV_META_TYPE_RAW)
    addmeta("TLV_META_TYPE_BOOL",      TLV_META_TYPE_BOOL)
    addmeta("TLV_META_TYPE_QWORD",     TLV_META_TYPE_QWORD)
    addmeta("TLV_META_TYPE_COMPRESSED",TLV_META_TYPE_COMPRESSED)
    addmeta("TLV_META_TYPE_GROUP",     TLV_META_TYPE_GROUP)
    addmeta("TLV_META_TYPE_COMPLEX",   TLV_META_TYPE_COMPLEX)

    addtype(TLV_META_TYPE_NONE,   "ANY",               0)
    addtype(TLV_META_TYPE_UINT,   "COMMAND_ID",        TLV_TYPE_COMMAND_ID)
    addtype(TLV_META_TYPE_STRING, "REQUEST_ID",        2)
    addtype(TLV_META_TYPE_GROUP,  "EXCEPTION",         3)
    addtype(TLV_META_TYPE_UINT,   "RESULT",            4)

    addtype(TLV_META_TYPE_STRING, "STRING",            10)
    addtype(TLV_META_TYPE_UINT,   "UINT",              11)
    addtype(TLV_META_TYPE_BOOL,   "BOOL",              12)

    addtype(TLV_META_TYPE_UINT, "LENGTH",              25)
    addtype(TLV_META_TYPE_RAW,  "DATA",                26)
    addtype(TLV_META_TYPE_UINT, "FLAGS",               27)

    addtype(TLV_META_TYPE_UINT,   "CHANNEL_ID",        50)
    addtype(TLV_META_TYPE_STRING, "CHANNEL_TYPE",      51)
    addtype(TLV_META_TYPE_RAW,    "CHANNEL_DATA",      52)
    addtype(TLV_META_TYPE_GROUP,  "CHANNEL_DATA_GROUP",53)
    addtype(TLV_META_TYPE_UINT,   "CHANNEL_CLASS",     54)

    addtype(TLV_META_TYPE_UINT, "SEEK_WHENCE",         70)
    addtype(TLV_META_TYPE_UINT, "SEEK_OFFSET",         71)
    addtype(TLV_META_TYPE_UINT, "SEEK_POS",            72)

    addtype(TLV_META_TYPE_UINT,   "EXCEPTION_CODE",    300)
    addtype(TLV_META_TYPE_STRING, "EXCEPTION_STRING",  301)

    addtype(TLV_META_TYPE_STRING, "LIBRARY_PATH",      400)
    addtype(TLV_META_TYPE_STRING, "TARGET_PATH",       401)
    addtype(TLV_META_TYPE_UINT,   "MIGRATE_PID",       402)
    addtype(TLV_META_TYPE_UINT,   "MIGRATE_LEN",       403)

    addtype(TLV_META_TYPE_STRING, "MACHINE_ID",        460)
    addtype(TLV_META_TYPE_RAW,    "UUID",              461)

    addtype(TLV_META_TYPE_STRING, "CIPHER_NAME",       500)
    addtype(TLV_META_TYPE_RAW,    "CIPHER_PARAMETERS", 501)

    addtype(TLV_META_TYPE_QWORD, "HANDLE",             600)
    addtype(TLV_META_TYPE_BOOL,  "INHERIT",            601)
    addtype(TLV_META_TYPE_QWORD, "PROCESS_HANDLE",     630)
    addtype(TLV_META_TYPE_QWORD, "THREAD_HANDLE",      631)

    addtype(TLV_META_TYPE_STRING, "DIRECTORY_PATH",    1200)
    addtype(TLV_META_TYPE_STRING, "FILE_NAME",         1201)
    addtype(TLV_META_TYPE_STRING, "FILE_PATH",         1202)
    addtype(TLV_META_TYPE_STRING, "FILE_MODE",         1203)
    addtype(TLV_META_TYPE_UINT,   "FILE_SIZE",         1204)
    addtype(TLV_META_TYPE_RAW,    "FILE_HASH",         1206)

    addtype(TLV_META_TYPE_COMPLEX, "STAT_BUF",         1220)

    addtype(TLV_META_TYPE_BOOL,   "SEARCH_RECURSE",    1230)
    addtype(TLV_META_TYPE_STRING, "SEARCH_GLOB",       1231)
    addtype(TLV_META_TYPE_STRING, "SEARCH_ROOT",       1232)
    addtype(TLV_META_TYPE_GROUP,  "SEARCH_RESULTS",    1233)

    addtype(TLV_META_TYPE_STRING, "HOST_NAME",         1400)
    addtype(TLV_META_TYPE_UINT,   "PORT",              1401)

    addtype(TLV_META_TYPE_RAW,   "SUBNET",             1420)
    addtype(TLV_META_TYPE_RAW,   "NETMASK",            1421)
    addtype(TLV_META_TYPE_RAW,   "GATEWAY",            1422)
    addtype(TLV_META_TYPE_GROUP, "NETWORK_ROUTE",      1423)

    addtype(TLV_META_TYPE_RAW,    "IP",                1430)
    addtype(TLV_META_TYPE_RAW,    "MAC_ADDRESS",       1431)
    addtype(TLV_META_TYPE_STRING, "MAC_NAME",          1432)
    addtype(TLV_META_TYPE_GROUP,  "NETWORK_INTERFACE", 1433)

    addtype(TLV_META_TYPE_STRING, "SUBNET_STRING",     1440)
    addtype(TLV_META_TYPE_STRING, "NETMASK_STRING",    1441)
    addtype(TLV_META_TYPE_STRING, "GATEWAY_STRING",    1442)

    addtype(TLV_META_TYPE_STRING, "PEER_HOST",         1500)
    addtype(TLV_META_TYPE_UINT,   "PEER_PORT",         1501)
    addtype(TLV_META_TYPE_STRING, "LOCAL_HOST",        1502)
    addtype(TLV_META_TYPE_UINT,   "LOCAL_PORT",        1503)
    addtype(TLV_META_TYPE_UINT,   "CONNECT_RETRIES",   1504)

    addtype(TLV_META_TYPE_UINT,  "SHUTDOWN_HOW",       1530)

    addtype(TLV_META_TYPE_QWORD,  "ROOT_KEY",          1000)
    addtype(TLV_META_TYPE_STRING, "BASE_KEY",          1001)
    addtype(TLV_META_TYPE_UINT,   "PERMISSION",        1002)
    addtype(TLV_META_TYPE_STRING, "KEY_NAME",          1003)
    addtype(TLV_META_TYPE_STRING, "VALUE_NAME",        1010)
    addtype(TLV_META_TYPE_UINT,   "VALUE_TYPE",        1011)
    addtype(TLV_META_TYPE_RAW,    "VALUE_DATA",        1012)

    addtype(TLV_META_TYPE_STRING, "COMPUTER_NAME",     1040)
    addtype(TLV_META_TYPE_STRING, "OS_NAME",           1041)
    addtype(TLV_META_TYPE_STRING, "USER_NAME",         1042)
    addtype(TLV_META_TYPE_STRING, "ARCHITECTURE",      1043)
    addtype(TLV_META_TYPE_STRING, "LANG_SYSTEM",       1044)

    addtype(TLV_META_TYPE_STRING, "ENV_VARIABLE",      1100)


    addtype(TLV_META_TYPE_QWORD, "BASE_ADDRESS",       2000)
    addtype(TLV_META_TYPE_UINT,  "ALLOCATION_TYPE",    2001)
    addtype(TLV_META_TYPE_UINT,  "PROTECTION",         2002)
    addtype(TLV_META_TYPE_UINT,  "PROCESS_PERMS",      2003)
    addtype(TLV_META_TYPE_RAW,   "PROCESS_MEMORY",     2004)
    addtype(TLV_META_TYPE_QWORD, "ALBASE_ADDRESS",     2005)
    addtype(TLV_META_TYPE_UINT,  "MEMORY_STATE",       2006)
    addtype(TLV_META_TYPE_UINT,  "MEMORY_TYPE",        2007)
    addtype(TLV_META_TYPE_UINT,  "ALPROTECTION",       2008)
    addtype(TLV_META_TYPE_UINT,  "PID",                2300)
    addtype(TLV_META_TYPE_STRING,"PROCESS_NAME",       2301)
    addtype(TLV_META_TYPE_STRING,"PROCESS_PATH",       2302)
    addtype(TLV_META_TYPE_GROUP, "PROCESS_GROUP",      2303)
    addtype(TLV_META_TYPE_UINT,  "PROCESS_FLAGS",      2304)
    addtype(TLV_META_TYPE_STRING,"PROCESS_ARGUMENTS",  2305)

    addtype(TLV_META_TYPE_STRING, "IMAGE_FILE",        2400)
    addtype(TLV_META_TYPE_STRING, "IMAGE_FILE_PATH",   2401)
    addtype(TLV_META_TYPE_STRING, "PROCEDURE_NAME",    2402)
    addtype(TLV_META_TYPE_QWORD,  "PROCEDURE_ADDRESS", 2403)
    addtype(TLV_META_TYPE_QWORD,  "IMAGE_BASE",        2404)
    addtype(TLV_META_TYPE_GROUP,  "IMAGE_GROUP",       2405)
    addtype(TLV_META_TYPE_STRING, "IMAGE_NAME",        2406)

    addtype(TLV_META_TYPE_UINT, "THREAD_ID",           2500)
    addtype(TLV_META_TYPE_UINT, "THREAD_PERMS",        2502)
    addtype(TLV_META_TYPE_UINT, "EXIT_CODE",           2510)
    addtype(TLV_META_TYPE_QWORD,"ENTRY_POINT",         2511)
    addtype(TLV_META_TYPE_QWORD,"ENTRY_PARAMETER",     2512)
    addtype(TLV_META_TYPE_UINT, "CREATION_FLAGS",      2513)

    addtype(TLV_META_TYPE_STRING,"REGISTER_NAME",      2540)
    addtype(TLV_META_TYPE_UINT,  "REGISTER_SIZE",      2541)
    addtype(TLV_META_TYPE_UINT,  "REGISTER_VALUE_32",  2542)
    addtype(TLV_META_TYPE_GROUP, "REGISTER",           2550)

    addtype(TLV_META_TYPE_UINT,  "IDLE_TIME",          3000)
    addtype(TLV_META_TYPE_STRING,"KEYS_DUMP",          3001)
    addtype(TLV_META_TYPE_STRING,"DESKTOP",            3002)

    addtype(TLV_META_TYPE_STRING, "EVENT_SOURCENAME",  4000)
    addtype(TLV_META_TYPE_QWORD, "EVENT_HANDLE",       4001)
    addtype(TLV_META_TYPE_UINT, "EVENT_NUMRECORDS",    4002)

    addtype(TLV_META_TYPE_UINT, "EVENT_READFLAGS",     4003)
    addtype(TLV_META_TYPE_UINT, "EVENT_RECORDOFFSET",  4004)

    addtype(TLV_META_TYPE_UINT,  "EVENT_RECORDNUMBER", 4006)
    addtype(TLV_META_TYPE_UINT,  "EVENT_TIMEGENERATED",4007)
    addtype(TLV_META_TYPE_UINT,  "EVENT_TIMEWRITTEN",  4008)
    addtype(TLV_META_TYPE_UINT,  "EVENT_ID",           4009)
    addtype(TLV_META_TYPE_UINT,  "EVENT_TYPE",         4010)
    addtype(TLV_META_TYPE_UINT,  "EVENT_CATEGORY",     4011)
    addtype(TLV_META_TYPE_STRING,"EVENT_STRING",       4012)
    addtype(TLV_META_TYPE_RAW,   "EVENT_DATA",         4013)

    addtype(TLV_META_TYPE_STRING, "ENV_VALUE",         1101)
    addtype(TLV_META_TYPE_GROUP,  "ENV_GROUP",         1102)

    addtype(TLV_META_TYPE_STRING, "MACHINE_ID",        460)
    addtype(TLV_META_TYPE_RAW,    "UUID",              461)
    addtype(TLV_META_TYPE_RAW,    "SESSION_GUID",      462)

    addtype(TLV_META_TYPE_RAW,  "RSA_PUB_KEY",         TLV_TYPE_RSA_PUB_KEY)
    addtype(TLV_META_TYPE_UINT, "SYM_KEY_TYPE",        551)
    addtype(TLV_META_TYPE_RAW,  "SYM_KEY",             552)
    addtype(TLV_META_TYPE_RAW,  "ENC_SYM_KEY",         TLV_TYPE_ENC_SYM_KEY)

    addcomm(0, "EXTENSION_ID_CORE")
    addcomm(COMMAND_ID_CORE_CHANNEL_CLOSE,            "CORE_CHANNEL_CLOSE")
    addcomm(COMMAND_ID_CORE_CHANNEL_EOF,              "CORE_CHANNEL_EOF")
    addcomm(COMMAND_ID_CORE_CHANNEL_INTERACT,         "CORE_CHANNEL_INTERACT")
    addcomm(COMMAND_ID_CORE_CHANNEL_OPEN,             "CORE_CHANNEL_OPEN")
    addcomm(COMMAND_ID_CORE_CHANNEL_READ,             "CORE_CHANNEL_READ")
    addcomm(COMMAND_ID_CORE_CHANNEL_SEEK,             "CORE_CHANNEL_SEEK")
    addcomm(COMMAND_ID_CORE_CHANNEL_TELL,             "CORE_CHANNEL_TELL")
    addcomm(COMMAND_ID_CORE_CHANNEL_WRITE,            "CORE_CHANNEL_WRITE")
    addcomm(COMMAND_ID_CORE_CONSOLE_WRITE,            "CORE_CONSOLE_WRITE")
    addcomm(COMMAND_ID_CORE_ENUMEXTCMD,               "CORE_ENUMEXTCMD")
    addcomm(COMMAND_ID_CORE_GET_SESSION_GUID,         "CORE_GET_SESSION_GUID")
    addcomm(COMMAND_ID_CORE_LOADLIB,                  "CORE_LOADLIB")
    addcomm(COMMAND_ID_CORE_MACHINE_ID,               "CORE_MACHINE_ID")
    addcomm(COMMAND_ID_CORE_MIGRATE,                  "CORE_MIGRATE")
    addcomm(COMMAND_ID_CORE_NATIVE_ARCH,              "CORE_NATIVE_ARCH")
    addcomm(COMMAND_ID_CORE_NEGOTIATE_TLV_ENCRYPTION, "CORE_NEGOTIATE_TLV_ENCRYPTION")
    addcomm(COMMAND_ID_CORE_PATCH_URL,                "CORE_PATCH_URL")
    addcomm(COMMAND_ID_CORE_PIVOT_ADD,                "CORE_PIVOT_ADD")
    addcomm(COMMAND_ID_CORE_PIVOT_REMOVE,             "CORE_PIVOT_REMOVE")
    addcomm(COMMAND_ID_CORE_PIVOT_SESSION_DIED,       "CORE_PIVOT_SESSION_DIED")
    addcomm(COMMAND_ID_CORE_SET_SESSION_GUID,         "CORE_SET_SESSION_GUID")
    addcomm(COMMAND_ID_CORE_SET_UUID,                 "CORE_SET_UUID")
    addcomm(COMMAND_ID_CORE_SHUTDOWN,                 "CORE_SHUTDOWN")
    addcomm(COMMAND_ID_CORE_TRANSPORT_ADD,            "CORE_TRANSPORT_ADD")
    addcomm(COMMAND_ID_CORE_TRANSPORT_CHANGE,         "CORE_TRANSPORT_CHANGE")
    addcomm(COMMAND_ID_CORE_TRANSPORT_GETCERTHASH,    "CORE_TRANSPORT_GETCERTHASH")
    addcomm(COMMAND_ID_CORE_TRANSPORT_LIST,           "CORE_TRANSPORT_LIST")
    addcomm(COMMAND_ID_CORE_TRANSPORT_NEXT,           "CORE_TRANSPORT_NEXT")
    addcomm(COMMAND_ID_CORE_TRANSPORT_PREV,           "CORE_TRANSPORT_PREV")
    addcomm(COMMAND_ID_CORE_TRANSPORT_REMOVE,         "CORE_TRANSPORT_REMOVE")
    addcomm(COMMAND_ID_CORE_TRANSPORT_SETCERTHASH,    "CORE_TRANSPORT_SETCERTHASH")
    addcomm(COMMAND_ID_CORE_TRANSPORT_SET_TIMEOUTS,   "CORE_TRANSPORT_SET_TIMEOUTS")
    addcomm(COMMAND_ID_CORE_TRANSPORT_SLEEP,          "CORE_TRANSPORT_SLEEP")

    comm_len = COMMAND_ID_CORE_TRANSPORT_SLEEP + 1
end
 
function find_tipo(value)
    if value == 0 then
        return metas[1]
    end
    for _, val in ipairs(types) do
        local tipo = bit.bor(val.kind, val.meta)
        if value == tipo then
            return val
        end
    end
    for _, val in ipairs(metas) do
        local tipo = val.meta
        if bit.band(value, tipo) == tipo then
            return val
        end
    end
    return nil
end

function extract_tlv_payload(decoded_buf, root, test)
    local length = decoded_buf(0,4):uint()
    if (length>decoded_buf:len()) then
        length = decoded_buf:len()
    end
    local tipo = decoded_buf(4,4):uint()
    local tip = find_tipo(tipo)
    local meta_tip
    local tip_name
    if tip == nil then
        meta_tip = 0
        tip_name = UNKNOWN
    else
        meta_tip = tip.meta
        tip_name = tip.name
    end

    local subtree = root:add(f_expr, decoded_buf(0,length)):append_text(" ["..tip_name.."]")

    subtree:add(f_length, decoded_buf(0,4), length)
    subtree:add(f_type, decoded_buf(4,4), tipo):append_text(" [Type: "..tip_name.."]")

    local payload
    local payload_len
    local payload_type
    if (meta_tip == TLV_META_TYPE_STRING) then
        payload_len = length - 8
        payload = decoded_buf(8, payload_len):raw()
        payload_type = f_payload_str
    elseif (meta_tip == TLV_META_TYPE_UINT) then
        payload_len = 4
        payload = decoded_buf(8,4):uint()
        payload_type = f_payload_uint32
    elseif (meta_tip == TLV_META_TYPE_QWORD) then
        payload_len = 8
        payload = decoded_buf(8,8):uint64()
        payload_type = f_payload_uint64
    elseif (meta_tip == TLV_META_TYPE_BOOL) then
        payload_len = 1
        payload = decoded_buf(8,1):int()
        payload_type = f_payload_int8
    elseif (meta_tip == TLV_META_TYPE_RAW) then
        payload_len = length - 8
        payload = decoded_buf(8, payload_len):raw()
        payload_type = f_payload_raw
    else
        payload_len = -1
        payload_type = f_payload_raw
    end
    if payload_len < 0 then
        subtree:add(payload_type, decoded_buf(8,length-8)):append_text(" [Value: Unreadable]")
    else
        local node = subtree:add(payload_type, decoded_buf(8,payload_len), payload)

        if (tip.kind == TLV_TYPE_COMMAND_ID) and (meta_tip == TLV_META_TYPE_UINT) then
            if payload < comm_len and payload >= 0 then
                node:append_text(" [Command ID: "..commands[payload].."]")
            end
        elseif (tip.kind == TLV_TYPE_RSA_PUB_KEY) and (meta_tip == TLV_META_TYPE_RAW) then
            PUB_RSA = der_to_pem(base64.encode(payload))
            local ra = ByteArray.new(PUB_RSA, true)
            local rsa_ = ra:tvb(DATA_PUBK)(0,ra:len())

            node:add(f_data,rsa_)

            local x = pkey.read(payload)
            if x ~= nil then
                RSA_PUB_KEY = x:get_public()

                node:add_expert_info(PI_DECRYPTION, PI_NOTE,  MSG_PUBK_FOUND)
            else
                node:add_expert_info(PI_DECRYPTION, PI_WARN,  ERR_PUBK_WRONG)
            end
        elseif (tip.kind == TLV_TYPE_ENC_SYM_KEY) and (meta_tip == TLV_META_TYPE_RAW)  then
            local pk = try_to_decrypt(payload, '')
            if pk ~= nil then
                -- get private rsa key

                subtree:add_expert_info(PI_DECRYPTION, PI_NOTE,  MSG_PRVK_FOUND)
                local ra = ByteArray.new(pk, true)
                local rsa_ = ra:tvb(DATA_PRVK)(0,ra:len())

                node:add(f_data,rsa_)
            else
                node:add_expert_info(PI_DECRYPTION, PI_WARN,  ERR_ECRYPTED)
            end
        end
    end

    if decoded_buf:len() > length then
        extract_tlv_payload(decoded_buf(length, decoded_buf:len()-length), root, test)
    end
end

local function xor_bytes(a,b,name) --Bitwise xor
    local res = b:bytes()
    local ab = a:bytes()
    local bb = b:bytes()
    for i = 0, (b:len() - 1) do
        res:set_index( i, bit.bxor(ab:get_index(i%4), bb:get_index(i)) )
    end
    return res:tvb(name)
end

-- myproto dissector function
function p_myproto.dissector (buf, pkt, root)
    local test = 0
  offset = pkt.desegment_offset or 0
  total_len = buf:len() - offset
  remain_len = total_len

  proto_added = false

  while (offset < total_len) do
    current_command_id = 0
    current_request_id = 0

    -- validate packet length is adequate, otherwise load more data
    -- len(xor) + len(header) + len(payload) >= 32
    -- len(xor) = 4
    -- len(header) = 28 = GUID(16)+enc(4)+len(4)+type(4)
    -- len(payload) >= 0
    if remain_len < 32 then
        pkt.desegment_offset = offset
        pkt.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
        return
    end

    -- xor buffer
    xor = buf(offset,4)
    -- header
    header = xor_bytes(xor, buf(offset+4,28), DATA_DECODED_HEADER)
    --
    command_enc = header(16,4):uint()
    if command_enc > 1 then
        return 0
    end

    -- (payload_size + 4) value
    len_array = header(20,4):uint()
    remain_len = remain_len - 32
    payload_len = len_array - 8

    -- len_array <= 8 is not bug but is the feature of Meterpreter,
    -- checking if we have the padding packet
    if len_array <= 8 then
        payload_len = 0
        goto continue
    end

    -- check the remain buffer is not less then the declared payload
    if remain_len < payload_len then
        if payload_len > 0x1000000 then
            return 0
        else
            -- load more bytes
            pkt.desegment_offset = offset
            pkt.desegment_len = DESEGMENT_ONE_MORE_SEGMENT --len_array + 24
            return
        end
    end

    -- declare the Meterpreter protocol
    pkt.cols.protocol:set(m_proto_name)
    if string.find(tostring(pkt.cols.info), "^".. m_proto_name) == nil then
        pkt.cols.info:set(m_proto_name)
    end


    -- read next packet description
    -- payload
    packtree = root:add(p_myproto, buf(offset,payload_len+32))
    packtree:add(f_xor_seg, buf(offset,4))
    packhead = packtree:add(f_packet_head, buf(offset+4,28))
    command_guid = header(0,16):raw()
    command_length = len_array
    command_type = header(24,4):uint()

    -- add protocol fields to the packet's head
    packhead:add(f_guid,    header(0,16), command_guid)
    encoded_f = 
    packhead:add(f_enc,     header(16,4), command_enc)
    packhead:add(f_length,  header(20,4), command_length)
    if command_type == 0 then
        command_type_string = TYPE_REQUEST
    elseif
        command_type == 1 then command_type_string = TYPE_RESPONSE
    elseif
        command_type == 10 then command_type_string = TYPE_PLAIN_REQUEST
    elseif
        command_type == 11 then command_type_string = TYPE_PLAIN_RESPONSE
    else
        packhead:add_expert_info(PI_PROTOCOL, PI_WARN,  ERR_UNKNOWN_TYPE)
        return 0
    end
    packtree:append_text(" [Length ".. command_length .."; Type: "..command_type_string)    
    if command_enc > 0 then
        local encoding
        packtree:append_text("; Encoded: ")
        if command_enc == 1 then
            encoding = ENC_AES256_CBC
        else
            encoding = UNKNOWN
        end
        encoded_f:append_text(' ['..encoding..']')
        packtree:append_text(encoding)
    end
    packtree:append_text(']')
    packhead:add(f_type, header(24,4), command_type):append_text(" [Packet type: ".. command_type_string .."]")

    if command_type == 0 or command_type == 1 then
        decoded_payload = xor_bytes(xor, buf(offset + 32,payload_len), DATA_DECODED_PAYLOAD)

        if command_enc > 0 then -- encrypted
            local irs = decoded_payload(0,16):raw()
            local node = packtree:add(f_payload_irs, decoded_payload(0,16))
            local decrypted_res = try_to_decrypt(decoded_payload(16,payload_len-16):raw(), irs)
            if decrypted_res == nil then
                local node = packtree:add(f_payload_raw, decoded_payload(16,payload_len-16)):append_text(" [Encrypted data]")
                node:add_expert_info(PI_DECRYPTION, PI_WARN,  ERR_ECRYPTED)
                goto continue
            else
                local ba = ByteArray.new(decrypted_res, true)
                decoded_payload = ba:tvb(DATA_DECRYPTED)(0,ba:len())
            end
        end

        payloadtree = packtree:add(f_packet_payload, buf(offset + 32,payload_len))
        extract_tlv_payload(decoded_payload, payloadtree, test)
    end
    ::continue::
    offset = offset + 32 + payload_len
    remain_len = remain_len - payload_len
  end

  return offset
end

p_myproto.prefs.keys = Pref.string("Private keys", "",
                                       "Private keys in format\n(openssl method):(key in hex format) splitted with ;\nFor example aes-256-cbc:00111e1f2f1f2e3fafae5;")

p_myproto.prefs.tcp_port  = Pref.uint("TCP Port number", default_settings.tcp_port, "The TCP port number for Meterpreter")

function p_myproto.prefs_changed()
    local need_reload = false

    if default_settings.keys ~= p_myproto.prefs.keys then
        default_settings.keys = p_myproto.prefs.keys
        -- have to reload the capture file for this type of change
        need_reload = true
    end

    if default_settings.tcp_port ~= p_myproto.prefs.tcp_port then
        -- remove old one, if not 0
        if default_settings.tcp_port ~= 0 then
            DissectorTable.get("tcp.port"):remove(default_settings.tcp_port, p_myproto)
        end
        -- set our new default
        default_settings.tcp_port = p_myproto.prefs.tcp_port
        -- add new one, if not 0
        if default_settings.tcp_port ~= 0 then
            DissectorTable.get("tcp.port"):add(default_settings.tcp_port, p_myproto)
        end
    end

    if need_reload then
        reload()
    end
end
 
-- Initialization routine
function p_myproto.init()
    initdata()
end
 
-- register a chained dissector for port 4444
local tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(default_settings.tcp_port, p_myproto)
