use actix_web::{web, HttpResponse, Result};
use serde_json;

// Test case for unvalidated redirect (#180)
pub async fn redirect_user(url: web::Query<String>) -> Result<HttpResponse> {
    Ok(HttpResponse::Found().header("Location", &url.into_inner()).finish())
}

// Test case for XML injection (#181)  
pub async fn xml_response(name: web::Query<String>) -> Result<HttpResponse> {
    let xml_body = format!("<user>{}</user>", name.into_inner());
    Ok(HttpResponse::Ok().content_type("application/xml").body(xml_body))
}

// Test case for NoSQL injection (#182)
pub async fn find_user(username: web::Query<String>) -> String {
    let query = format!("{{\"username\": \"{}\"}}", username.into_inner());
    query
}

// Test case for GraphQL injection (#183)
pub async fn execute_graphql(query: web::Query<String>) -> String {
    let graphql_query = format!("query {{ user(id: {}) }}", query.into_inner());
    graphql_query
}

// Test case for improper input validation (#184)
pub async fn process_json(data: web::Json<serde_json::Value>) -> Result<HttpResponse> {
    // No validation on deserialized user input
    let result = serde_json::from_str(&data.to_string()).unwrap();
    Ok(HttpResponse::Ok().json(result))
}