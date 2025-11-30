use axum::{
    http::StatusCode,
    routing::{get, post, put},
    Router,
};
use axum_login::login_required;
use axum_messages::Message;
use serde::{Deserialize, Serialize};

use crate::restful::users::Backend;

use super::{
    users::{AuthSession, Credentials},
    AppStateInner,
};

#[derive(Debug, Deserialize, Serialize)]
pub struct LoginResult {
    messages: Vec<Message>,
}

pub fn router() -> Router<AppStateInner> {
    let r = Router::new()
        .route("/api/v1/auth/password", put(self::put::change_password))
        .route(
            "/api/v1/auth/check_login_status",
            get(self::get::check_login_status),
        )
        .route_layer(login_required!(Backend));
    Router::new()
        .merge(r)
        .route("/api/v1/auth/login", post(self::post::login))
        .route("/api/v1/auth/logout", get(self::get::logout))
        .route("/api/v1/auth/captcha", get(self::get::get_captcha))
        .route("/api/v1/auth/register", post(self::post::register))
}

mod put {
    use axum::Json;
    use axum_login::AuthUser;
    use easytier::proto::common::Void;

    use crate::restful::{other_error, users::ChangePassword, HttpHandleError};

    use super::*;

    pub async fn change_password(
        mut auth_session: AuthSession,
        Json(req): Json<ChangePassword>,
    ) -> Result<Json<Void>, HttpHandleError> {
        if let Err(e) = auth_session
            .backend
            .change_password(auth_session.user.as_ref().unwrap().id(), &req)
            .await
        {
            tracing::error!("修改密码失败: {:?}", e);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json::from(other_error(format!("修改密码失败: {:?}", e))),
            ));
        }

        let _ = auth_session.logout().await;

        Ok(Void::default().into())
    }
}

mod post {
    use axum::Json;
    use easytier::proto::common::Void;

    use crate::restful::{
        captcha::extension::{axum_tower_sessions::CaptchaAxumTowerSessionStaticExt, CaptchaUtil},
        other_error,
        users::RegisterNewUser,
        HttpHandleError,
    };

    use super::*;

    pub async fn login(
        mut auth_session: AuthSession,
        Json(creds): Json<Credentials>,
    ) -> Result<Json<Void>, HttpHandleError> {
        let user = match auth_session.authenticate(creds.clone()).await {
            Ok(Some(user)) => user,
            Ok(None) => {
                return Err((
                    StatusCode::UNAUTHORIZED,
                    Json::from(other_error("用户名或密码错误")),
                ));
            }
            Err(e) => {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json::from(other_error(format!("服务器内部错误: {:?}", e))),
                ))
            }
        };

        if let Err(e) = auth_session.login(&user).await {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json::from(other_error(format!("登录失败: {:?}", e))),
            ));
        }

        Ok(Void::default().into())
    }

    pub async fn register(
        auth_session: AuthSession,
        captcha_session: tower_sessions::Session,
        Json(req): Json<RegisterNewUser>,
    ) -> Result<Json<Void>, HttpHandleError> {
        // 调用CaptchaUtil的静态方法验证验证码是否正确
        if !CaptchaUtil::ver(&req.captcha, &captcha_session).await {
            return Err((
                StatusCode::BAD_REQUEST,
                other_error(format!("验证码错误，输入值: {}", req.captcha)).into(),
            ));
        }

        if let Err(_e) = auth_session.backend.register_new_user(&req).await {
    tracing::error!("注册失败，本站已关闭注册");
    return Err((StatusCode::BAD_REQUEST, axum::Json(other_error("禁止注册"))));
}

Ok(Void::default().into())

mod get {
    use crate::restful::{
        captcha::{
            builder::spec::SpecCaptcha,
            extension::{axum_tower_sessions::CaptchaAxumTowerSessionExt as _, CaptchaUtil},
            NewCaptcha as _,
        },
        other_error, HttpHandleError,
    };
    use axum::{response::Response, Json};
    use easytier::proto::common::Void;
    use tower_sessions::Session;

    use super::*;

    pub async fn logout(mut auth_session: AuthSession) -> Result<Json<Void>, HttpHandleError> {
        match auth_session.logout().await {
            Ok(_) => Ok(Json(Void::default())),
            Err(e) => {
                tracing::error!("退出登录失败: {:?}", e);
                Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json::from(other_error(format!("退出登录失败: {:?}", e))),
                ))
            }
        }
    }

    pub async fn get_captcha(session: Session) -> Result<Response, HttpHandleError> {
        let mut captcha: CaptchaUtil<SpecCaptcha> = CaptchaUtil::with_size_and_len(127, 48, 4);
        match captcha.out(&session).await {
            Ok(response) => Ok(response),
            Err(e) => Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json::from(other_error(format!("生成验证码失败: {:?}", e))),
            )),
        }
    }

    pub async fn check_login_status(
    auth_session: AuthSession,
) -> Result<Json<Void>, HttpHandleError> {
    if auth_session.user.is_some() {
        Ok(Json(Void::default()))
    } else {
        Err((StatusCode::UNAUTHORIZED, Json::from(other_error("未登录"))))
    }
}
