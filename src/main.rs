#[macro_use] extern crate rocket;

use rocket::serde::json::Json;
use rocket::serde::Serialize;
use rocket::http::Status;
use lightning::ln::{PaymentPreimage, PaymentHash};

mod lsat;
mod middleware;
mod utils;
mod macaroon;

#[derive(Serialize)]
#[serde(crate = "rocket::serde")]

struct Response {
    code: u16,
    message: String
}

#[get("/")]
fn free() -> Json<Response> {
    let response = Response {
        code: Status::Ok.code,
        message: String::from("Free content"),
    };

    Json(response)
}

#[get("/protected")]
fn protected() -> Json<Response> {
    // let lsatInfo = request.headers().get_one("LSAT").unwrap() as lsat::&LsatInfo;
    let lsat_info = lsat::LsatInfo {
        lsat_type: String::from("PAID"),
        preimage: PaymentPreimage([0; 32]),
        payment_hash: PaymentHash([0; 32]),
        amount: 10000,
        error: String::from("Error")
    };
    let lsat_info_type = lsat_info.lsat_type.to_string();
    let response = match lsat_info_type.as_str() {
        lsat::LSAT_TYPE_FREE => {
            Response {
                code: Status::Ok.code,
                message: String::from("Free content"),
            }
        }
        lsat::LSAT_TYPE_PAID => {
            Response {
                code: Status::Ok.code,
                message: String::from("Protected content"),
            }
        }
        lsat::LSAT_TYPE_ERROR => {
            Response {
                code: Status::InternalServerError.code,
                message: format!("{}", lsat_info.error),
            }
        }
        _ => {
            // Handle other cases
            Response {
                code: Status::InternalServerError.code,
                message: String::from("Unknown type"),
            }
        }
    };

    Json(response)
}

#[launch]
fn rocket() -> rocket::Rocket<rocket::Build> {
    rocket::build()
        .attach(middleware::LsatMiddleware)
        .mount("/", routes![free, protected])
}