use rocket::{Request};
use rocket::fairing::{Fairing, Info, Kind};
use rocket::Data;

use crate::utils;

pub struct LsatMiddleware;

#[rocket::async_trait]
impl Fairing for LsatMiddleware {
    fn info(&self) -> Info {
        Info {
            name: "Lsat Middleware",
            kind: Kind::Request,
        }
    }

    async fn on_request(&self, request: &mut Request<'_>, _: &mut Data<'_>) {
        if let Some(auth_field) = request.headers().get_one("Authorization") {
            match utils::parse_lsat_header(auth_field) {
                Ok((mac, preimage)) => {
                    // Use mac and preimage here
                },
                Err(error) => {
                    println!("Error parsing LSAT header: {}", error);
                },
            }
        }
    }
}
