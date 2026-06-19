pub mod block;

use serde::Deserialize;

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct GqlResponse<T> {
    pub data: GqlData<T>,
}

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct GqlData<T> {
    pub blockchain: T,
}

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct GqlEdge<T> {
    pub node: T,
}
