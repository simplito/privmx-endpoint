#ifndef _PRIVMXLIB_UTILS_SERVERERRORCODES_HPP_
#define _PRIVMXLIB_UTILS_SERVERERRORCODES_HPP_


namespace privmx {
namespace utils {

class ServerErrorCodes {
public:
    static const int PARSE_ERROR = -32700;
    static const int INVALID_REQUEST = -32600;
    static const int METHOD_NOT_FOUND = -32601;
    static const int INVALID_PARAMS = -32602;
    static const int INTERNAL_ERROR = -32603;
    static const int NOT_YET_INSTALLED = -32604;
    static const int ONLY_POST_METHOD_ALLOWED = -32605;
    
    static const int UNKNOWN_ERROR = 0x0001;
    static const int INVALID_USERNAME = 0x0002;
    static const int INVALID_SALT = 0x0003;
    static const int INVALID_VERIFIER = 0x0004;
    static const int INVALID_PRIV_DATA = 0x0005;
    static const int INVALID_IDENTITY_KEY = 0x0006;
    static const int USER_ALREADY_EXISTS = 0x0007;
    static const int INVALID_SIGNATURE = 0x0008;
    static const int USER_DOESNT_EXIST = 0x0009;
    static const int INVALID_USER_ENTRY = 0x000B;
    static const int UNKNOWN_SESSION = 0x000C;
    static const int INVALID_SESSION_STATE = 0x000D;
    static const int INVALID_A = 0x000E;
    static const int DIFFERENT_M1 = 0x000F;
    static const int INVALID_PIN = 0x0010;
    static const int OPEN_REGISTRATION_DISABLED = 0x0011;
    static const int MAX_PIN_ATTEMPTS_EXCEEDED = 0x0012;
    static const int USER_ALREADY_ACTIVATED = 0x0013;
    static const int INVITATION_DISABLED = 0x0014;
    static const int INVALID_TOKEN = 0x0015;
    static const int MAX_SIZE_OF_BLOCK_BULK_EXCEEDED = 0x0016;
    static const int INVALID_BID = 0x0017;
    static const int INVALID_DATA = 0x0018;
    static const int BLOCK_DOESNT_EXIST = 0x0019;
    static const int MAX_SIZE_OF_DESCRIPTOR_BULK_EXCEEDED = 0x001A;
    static const int INVALID_DESCRIPTOR_SIGNATURE_PAIR = 0x001B;
    static const int INVALID_DID = 0x001C;
    static const int DESCRIPTOR_DOESNT_EXIST = 0x001D;
    static const int INVALID_DPUB58 = 0x001E;
    static const int INVALID_JSON_PARAMETERS = 0x001F;
    static const int DPUB58_DOESNT_MATCH_TO_DID = 0x0020;
    static const int PUBLIC_KEY_CANNOT_BE_CHANGED = 0x0021;
    static const int OLD_SIGNATURE_DOESNT_MATCH = 0x0022;
    static const int INVALID_OWNER_SIGNATURE = 0x0024;
    static const int INVALID_SID = 0x0025;
    static const int INVALID_CREATE_SIGNATURE = 0x0026;
    static const int SINK_DOESNT_EXISTS = 0x0027;
    static const int INVALID_TIMESTAMP = 0x0028;
    static const int INVALID_NONCE = 0x0029;
    static const int INVALID_MID = 0x002A;
    static const int MESSAGE_DOESNT_EXISTS = 0x002B;
    static const int MAX_SIZE_OF_MESSAGE_BULK_EXCEEDED = 0x002C;
    static const int INVALID_HASHMAIL = 0x002D;
    static const int INVALID_USER_PRESENCE = 0x002E;
    static const int INVALID_SINK_ACL = 0x002F;
    static const int ACCESS_DENIED = 0x0030;
    static const int INVALID_STATE = 0x0031;
    static const int SINK_ALREADY_EXISTS = 0x0032;
    static const int INVALID_MOD_SEQ = 0x0033;
    static const int DESCRIPTOR_ALREADY_EXISTS = 0x0034;
    static const int INVALID_LOGIN_DATA = 0x0035;
    static const int INVALID_HOST = 0x0036;
    static const int INVALID_DESCRIPTOR_LOCK = 0x0037;
    static const int DESCRIPTOR_LOCKED = 0x0038;
    static const int INVALID_EMAIL = 0x0039;
    static const int INVALID_LANGUAGE = 0x003A;
    static const int INVALID_DESCRIPTION = 0x003B;
    static const int MAX_USERS_COUNT_EXCEEDED = 0x003C;
    static const int LOGIN_BLOCKED = 0x003D;
    static const int INVALID_SMTP_CONFIG = 0x003E;
    static const int CANNOT_SAVE_CONFIG = 0x003F;
    static const int LOGIN_REJECTED = 0x0040;
    static const int HOST_BLACKLISTED = 0x0041;
    static const int INVALID_BLOCK_SOURCE = 0x0042;
    static const int INVALID_TRANSFER_SESSION = 0x0043;
    static const int MAX_COUNT_OF_BLOCKS_EXCEEDED = 0x0044;
    static const int SECURE_FORM_VALIDATION_FAILED = 0x0045;
    static const int FORBIDDEN_USERNAME = 0x0046;
    static const int INVALID_DOCUMENT_ID = 0x0047;
    static const int DOCUMENT_DOESNT_EXISTS = 0x0048;
    static const int INVALID_PKI_DOCUMENT = 0x0049;
    static const int KVDB_DOESNT_EXIST = 0x0050;
    static const int KVDB_ALREADY_EXISTS = 0x0051;
    static const int KVDB_ENTRY_DOESNT_EXIST = 0x0052;
    static const int KVDB_ENTRY_LOCKED = 0x0053;
    static const int EVENT_LOG_DOESNT_EXIST = 0x0054;
    static const int EVENT_LOG_ALREADY_EXISTS = 0x0055;
    static const int FORM_DOESNT_EXIST = 0x0056;
    static const int FORM_ALREADY_EXISTS = 0x0057;
    static const int FORM_NAME_ALREADY_IN_USE = 0x0058;
    static const int USER_GROUP_DOESNT_EXIST = 0x0059;
    static const int USER_GROUP_ALREADY_EXISTS = 0x0060;
    static const int SECTION_DOESNT_EXIST = 0x0061;
    static const int SECTION_ALREADY_EXISTS = 0x0062;
    static const int INVALID_VERSION = 0x0063;
    static const int INVALID_DEVICE_ID = 0x0064;
    static const int PUB_KEY_ALREADY_IN_USE = 0x0065;
    static const int INVALID_LOGIN = 0x0066;
    static const int NO_ADMIN_FOR_EXTERNAL_USER = 0x0067;
    static const int MAINTENANCE_MODE = 0x0068;
    static const int INVALID_PROXY_SESSION = 0x0069;
    static const int SERVER_PROXY_ALREADY_EXISTS = 0x006A;
    static const int SERVER_PROXY_DOES_NOT_EXIST = 0x006B;
    static const int DATA_CENTER_DISABLED = 0x0069;
    static const int SECTIONS_LIMIT_EXCEEDED = 0x006A;
    static const int USER_BLOCKED = 0x006B;
    static const int DEVICE_DOES_NOT_EXIST = 0x006C;
    static const int DEVICE_BLOCKED = 0x006D;
    static const int IP_DOES_NOT_EXIST = 0x006E;
    static const int LOGIN_LOG_DOES_NOT_EXIST = 0x006F;
    static const int INVALID_KEY = 0x0070;
    static const int PRIVMX_STREAM_DISABLED = 0x0071;
    static const int WEBSOCKET_REQUIRED = 0x0072;
    static const int WEBSOCKET_ALREADY_AUTHORIZED = 0x0073;
    static const int INVALID_DESCRIPTOR_ACL = 0x0074;
    static const int DESCRIPTOR_GROUP_DOES_NOT_EXIST = 0x0075;
    static const int VIDEO_DISABLED = 0x0076;
    static const int VIDEO_ROOM_DOES_NOT_EXIST = 0x0077;
    static const int VIDEO_ROOM_ALREADY_CREATED = 0x0078;
    static const int VIDEO_ROOM_NOT_READY_YET = 0x0079;
    static const int CANNOT_JOIN_TO_VIDEO_ROOM = 0x0080;
    static const int NEED_2FA_AUTHENTICATION = 0x0081;
    static const int TOKEN_ALREADY_USED = 0x0082;
    static const int PUSH_NOTIFICATION_ALREADY_EXIST = 0x0083;
    static const int PUSH_NOTIFICATION_ENDPOINT_MISMATCH = 0x0084;
    static const int EXCEEDED_LIMIT_OF_WEBSOCKET_CHANNELS = 0x0085;
    static const int ADD_WS_CHANNEL_ID_REQUIRED_ON_MULTI_CHANNEL_WEBSOCKET = 0x0086;
    static const int CANNOT_ADD_CHANNEL_TO_SINGLE_CHANNEL_WEBSOCKET = 0x0087;
    static const int INVALID_CALENDAR_DATA = 0x0088;
    static const int CALENDAR_ENTRY_DOES_NOT_EXIST = 0x0089;
    static const int PAST_CALENDAR_IS_NOT_AVAILABLE = 0x008A;
    static const int DATE_OUT_OF_RANGE = 0x008B;
    static const int SECTION_KEY_ENCRYPTOR_MISMATCH = 0x008C;
    static const int SECTION_KEYS_VERSION_MISMATCH = 0x008D;
    static const int CALENDAR_ALREADY_ACTIVATED = 0x008E;
    static const int INVALID_CALENDAR_PUBLIC_VIEW_VERSION = 0x008F;
    static const int ACCESS_TO_SECTION_DENIED_FOR_SUBIDENTITY = 0x0090;
    static const int SUBIDENTITY_DOES_NOT_EXISTS = 0x0091;
    static const int DESCRIPTOR_VERSION_DOESNT_EXIST = 0x0092;
    static const int SHARE_DOES_NOT_EXIST = 0x0093;
    static const int INVALID_SHARE_TYPE = 0x0094;
    static const int REGISTRATION_FOR_CUSTOMERS_IS_DISABLED = 0x0095;
    static const int NO_JITSI_SCRIPT = 0x0096;
    static const int VIDEO_LIMIT_EXCEEDED = 0x0097;
    static const int GROUP_DOESNT_EXIST = 0x0098;
    static const int CANNOT_CHANGE_GROUP_PUB_KEY = 0x0099;
    static const int CANNOT_ALTER_USER_RIGHTS = 0x009A;
    
    static const int TWOFA_NOT_ENABLED = 0x7001;
    static const int TWOFA_INVALID_TYPE = 0x7002;
    static const int TWOFA_CODE_ALREADY_RESEND = 0x7003;
    static const int TWOFA_INVALID_GOOGLE_AUTHENTICATOR_SECRET = 0x7004;
    static const int TWOFA_EMAIL_REQUIRED = 0x7005;
    static const int TWOFA_MOBILE_REQUIRED = 0x7006;
    static const int TWOFA_INVALID_CODE = 0x7007;
    static const int TWOFA_VERIFICATION_FAILED = 0x7008;
    static const int TWOFA_INVALID_SESSION = 0x7009;
    static const int TWOFA_CANNOT_SEND_CODE = 0x7010;
    static const int TWOFA_CODE_ALREADY_USED = 0x7011;
};





} // utils
} // privmx

#endif // _PRIVMXLIB_UTILS_SERVERERRORCODES_HPP_