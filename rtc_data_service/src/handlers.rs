use actix::Addr;
use actix_web::{error::ErrorInternalServerError, get, post, web, HttpRequest, HttpResponse};
use models::Status;

use crate::enclave_actor::*;
use crate::merge_error::*;

pub async fn server_status(_req: HttpRequest) -> HttpResponse {
    HttpResponse::Ok().json(Status {
        status: "The server is up".to_string(),
    })
}

#[get("/data/attest")]
pub async fn data_enclave_attestation(
    _req: HttpRequest,
    enclave: web::Data<Addr<EnclaveActor>>,
) -> actix_web::Result<String> {
    let jwt = enclave
        .send(RequestAttestation::default())
        .await
        .merge_err();
    dbg!(&jwt);

    match jwt {
        Ok(result) => Ok(result),
        // TODO: Look at the result here - change the error format and see if we want to sanitise the output in some way
        Err(err) => Err(ErrorInternalServerError(err)),
    }
}

#[post("/data/upload/encrypted")]
pub async fn upload_encrypted_file(
    _req: HttpRequest,
    // enclave: web::Data<Addr<EnclaveActor>>,
) -> actix_web::Result<String> {
    println!("Inside Post Req");
    // let uploadResponse = enclave
    //     .send(DataPayload)
    //     .await;

    
    let response : Result<String, &str> = Ok("Successful".to_string());
    match response {
        Ok(response) => Ok(response),
        Err(err) => Err(ErrorInternalServerError(err)),
    }
}

pub mod models {
    use serde::Serialize;

    #[derive(Serialize)]
    pub struct Status {
        pub status: String,
    }
}
