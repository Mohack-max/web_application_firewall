#[derive(Debug)]
pub struct BlockedRequest(pub String);

impl warp::reject::Reject for BlockedRequest {}
