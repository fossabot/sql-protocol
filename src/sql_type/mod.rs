use std::collections::HashMap;

enum MysqlType {
    // NULL_TYPE specifies a NULL type.
    TypeNullType = 0,
    // INT8 specifies a TINYINT type.
    // Properties: 1, IsNumber.
    TypeInt8 = 257,
    // UINT8 specifies a TINYINT UNSIGNED type.
    // Properties: 2, IsNumber, IsUnsigned.
    TypeUint8 = 770,
    // INT16 specifies a SMALLINT type.
    // Properties: 3, IsNumber.
    TypeInt16 = 259,
    // UINT16 specifies a SMALLINT UNSIGNED type.
    // Properties: 4, IsNumber, IsUnsigned.
    TypeUint16 = 772,
    // INT24 specifies a MEDIUMINT type.
    // Properties: 5, IsNumber.
    TypeInt24 = 261,
    // UINT24 specifies a MEDIUMINT UNSIGNED type.
    // Properties: 6, IsNumber, IsUnsigned.
    TypeUint24 = 774,
    // INT32 specifies a INTEGER type.
    // Properties: 7, IsNumber.
    TypeInt32 = 263,
    // UINT32 specifies a INTEGER UNSIGNED type.
    // Properties: 8, IsNumber, IsUnsigned.
    TypeUint32 = 776,
    // INT64 specifies a BIGINT type.
    // Properties: 9, IsNumber.
    TypeInt64 = 265,
    // UINT64 specifies a BIGINT UNSIGNED type.
    // Properties: 10, IsNumber, IsUnsigned.
    TypeUint64 = 778,
    // FLOAT32 specifies a FLOAT type.
    // Properties: 11, IsFloat.
    TypeFloat32 = 1035,
    // FLOAT64 specifies a DOUBLE or REAL type.
    // Properties: 12, IsFloat.
    TypeFloat64 = 1036,
    // TIMESTAMP specifies a TIMESTAMP type.
    // Properties: 13, IsQuoted.
    TypeTimestamp = 2061,
    // DATE specifies a DATE type.
    // Properties: 14, IsQuoted.
    TypeDate = 2062,
    // TIME specifies a TIME type.
    // Properties: 15, IsQuoted.
    TypeTime = 2063,
    // DATETIME specifies a DATETIME type.
    // Properties: 16, IsQuoted.
    TypeDatetime = 2064,
    // YEAR specifies a YEAR type.
    // Properties: 17, IsNumber, IsUnsigned.
    TypeYear = 785,
    // DECIMAL specifies a DECIMAL or NUMERIC type.
    // Properties: 18, None.
    TypeDecimal = 18,
    // TEXT specifies a TEXT type.
    // Properties: 19, IsQuoted, IsText.
    TypeText = 6163,
    // BLOB specifies a BLOB type.
    // Properties: 20, IsQuoted, IsBinary.
    TypeBlob = 10260,
    // VARCHAR specifies a VARCHAR type.
    // Properties: 21, IsQuoted, IsText.
    TypeVarchar = 6165,
    // VARBINARY specifies a VARBINARY type.
    // Properties: 22, IsQuoted, IsBinary.
    TypeVarBinary = 10262,
    // CHAR specifies a CHAR type.
    // Properties: 23, IsQuoted, IsText.
    TypeChar = 6167,
    // BINARY specifies a BINARY type.
    // Properties: 24, IsQuoted, IsBinary.
    TypeBinary = 10264,
    // BIT specifies a BIT type.
    // Properties: 25, IsQuoted.
    TypeBit = 2073,
    // ENUM specifies an ENUM type.
    // Properties: 26, IsQuoted.
    TypeEnum = 2074,
    // SET specifies a SET type.
    // Properties: 27, IsQuoted.
    TypeSet = 2075,
    // TUPLE specifies a tuple. This cannot
    // be returned in a QueryResult, but it can
    // be sent as a bind var.
    // Properties: 28, None.
    TypeTuple = 28,
    // GEOMETRY specifies a GEOMETRY type.
    // Properties: 29, IsQuoted.
    TypeGeometry = 2077,
    // JSON specifies a JSON type.
    // Properties: 30, IsQuoted.
    TypeJson = 2078,
    // EXPRESSION specifies a SQL expression.
    // This type is for internal use only.
    // Properties: 31, None.
    TypeExpression = 31,
}

pub enum MysqlFlag {
    MysqlUnsigned = 32,
    MysqlBinary = 128,
    MysqlEnum = 256,
    MysqlSet = 2048,
}

pub type Type = i32;

#[derive(Default)]
pub struct Value {
    pub typ: Type,
    pub val: Vec<u8>,
}

#[derive(Default)]
pub struct Field {
    pub name: String,
    pub typ: i32,
    pub table: String,
    pub org_table: String,
    pub database: String,
    pub org_name: String,
    pub column_len: u32,
    pub charset: u32,
    pub decimals: u32,
    pub flags: u32,
}

#[derive(Default)]
pub struct SqlResult {
    pub fields: Vec<Field>,
    pub affected_rows: u64,
    pub insert_id: u64,
    pub rows: Vec<Vec<Value>>,
}

impl Value {
    pub fn is_null(&self) -> bool {
        self.typ == MysqlType::TypeNullType as Type
    }
}

lazy_static! {
    static ref TYPE_TO_MYSQL: HashMap<i32, (i64,i64)> = {
        let mut m = HashMap::new();
        m.insert(MysqlType::TypeInt8 as i32, (1, 0));
        m.insert(MysqlType::TypeUint8 as i32, (1, MysqlFlag::MysqlUnsigned as i64));
        m.insert(MysqlType::TypeInt16 as i32, (2, 0));
        m.insert(MysqlType::TypeUint16 as i32, (2, MysqlFlag::MysqlUnsigned as i64));
        m.insert(MysqlType::TypeInt32 as i32, (3, 0));
        m.insert(MysqlType::TypeUint32 as i32, (3, MysqlFlag::MysqlUnsigned as i64));
        m.insert(MysqlType::TypeFloat32 as i32, (4, 0));
        m.insert(MysqlType::TypeFloat64 as i32, (5, 0));
        m.insert(MysqlType::TypeNullType as i32, (6, MysqlFlag::MysqlBinary as i64));
        m.insert(MysqlType::TypeTimestamp as i32, (7, 0));
        m.insert(MysqlType::TypeInt64 as i32, (8, 0));
        m.insert(MysqlType::TypeUint64 as i32, (8, MysqlFlag::MysqlUnsigned as i64));
        m.insert(MysqlType::TypeInt24 as i32, (9, 0));
        m.insert(MysqlType::TypeUint24 as i32, (9, MysqlFlag::MysqlUnsigned as i64));
        m.insert(MysqlType::TypeDate as i32, (10, MysqlFlag::MysqlBinary as i64));
        m.insert(MysqlType::TypeTime as i32, (11, MysqlFlag::MysqlBinary as i64));
        m.insert(MysqlType::TypeDatetime as i32, (12, MysqlFlag::MysqlBinary as i64));
        m.insert(MysqlType::TypeYear as i32, (13, MysqlFlag::MysqlUnsigned as i64));
        m.insert(MysqlType::TypeBit as i32, (16, MysqlFlag::MysqlUnsigned as i64));
        m.insert(MysqlType::TypeJson as i32, (245, 0));
        m.insert(MysqlType::TypeDecimal as i32, (246, 0));
        m.insert(MysqlType::TypeText as i32, (252, 0));
        m.insert(MysqlType::TypeBlob as i32, (252, MysqlFlag::MysqlBinary as i64));
        m.insert(MysqlType::TypeVarchar as i32, (253, 0));
        m.insert(MysqlType::TypeVarBinary as i32, (253, MysqlFlag::MysqlBinary as i64));
        m.insert(MysqlType::TypeChar as i32, (254, 0));
        m.insert(MysqlType::TypeBinary as i32, (254, MysqlFlag::MysqlBinary as i64));
        m.insert(MysqlType::TypeEnum as i32, (254, MysqlFlag::MysqlEnum as i64));
        m.insert(MysqlType::TypeSet as i32, (254, MysqlFlag::MysqlSet as i64));
        m.insert(MysqlType::TypeGeometry as i32, (255, 0));
        m
    };
}

pub fn type_to_mysql(typ: Type) -> (i64, i64) {
    // Return (type, flag), flag could be zero
    let result: Option<&(i64, i64)> = TYPE_TO_MYSQL.get(&typ);
    return match result {
        Some(s) => {
            (s.0, s.1)
        }
        _ => { panic!("Unexpected"); }
    };
}