use wasm_bindgen::prelude::wasm_bindgen;

pub(crate) mod crypto;

#[wasm_bindgen(typescript_custom_section)]
const TS_TYPES: &str = r#"
export type TKeyPair = {
    public: string;
    secret: string;
};

export type TParamsOfSign = {
    unsigned: string;
    keys: TKeyPair;
}
"#;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "TParamsOfSign")]
    pub type TParamsOfSign;
}
