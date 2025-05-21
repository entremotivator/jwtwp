import streamlit as st
import jwt
import datetime
import json
import base64
import time
import uuid
import pytz

# Page configuration
st.set_page_config(
    page_title="WordPress JWT Token Creator",
    page_icon="🔑",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        margin-bottom: 1rem;
    }
    .sub-header {
        font-size: 1.5rem;
        margin-top: 2rem;
        margin-bottom: 1rem;
    }
    .info-box {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        margin-bottom: 1rem;
    }
    .success-box {
        background-color: #d1e7dd;
        padding: 1rem;
        border-radius: 0.5rem;
        margin-bottom: 1rem;
    }
    .warning-box {
        background-color: #fff3cd;
        padding: 1rem;
        border-radius: 0.5rem;
        margin-bottom: 1rem;
    }
    .error-box {
        background-color: #f8d7da;
        padding: 1rem;
        border-radius: 0.5rem;
        margin-bottom: 1rem;
    }
    .footer {
        margin-top: 3rem;
        text-align: center;
        color: #6c757d;
    }
</style>
""", unsafe_allow_html=True)

# Title and introduction
st.markdown('<div class="main-header">WordPress JWT Token Creator</div>', unsafe_allow_html=True)
st.markdown("""
This application helps you create and validate JWT (JSON Web Token) tokens for WordPress authentication.
These tokens can be used with WordPress JWT authentication plugins like 'JWT Authentication for WP REST API'.
""")

# Tabs
tab1, tab2, tab3 = st.tabs(["Token Generator", "Token Validator", "Documentation"])

with tab1:
    with st.sidebar:
        st.header("Configuration")
        jwt_secret = st.text_input("JWT Secret Key", type="password")
        algorithm = st.selectbox("Algorithm", ["HS256", "HS384", "HS512"])
        st.markdown("---")
        st.subheader("Advanced Settings")
        include_jti = st.checkbox("Include JTI (JWT ID)", True)
        include_aud = st.checkbox("Include Audience (aud)", False)
        audience = st.text_input("Audience Value", "wordpress-site", disabled=not include_aud)

    st.markdown('<div class="sub-header">Token Details</div>', unsafe_allow_html=True)
    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Basic Information")
        user_id = st.number_input("User ID", min_value=1, value=1)
        username = st.text_input("Username")
        email = st.text_input("Email")
        st.markdown("---")
        st.subheader("WordPress-specific Claims")
        site_url = st.text_input("Site URL", value="https://example.com")
        user_roles = st.multiselect("User Roles", 
            ["administrator", "editor", "author", "contributor", "subscriber"], default=["subscriber"])

    with col2:
        st.subheader("Token Settings")
        timezone = st.selectbox("Timezone", pytz.all_timezones, index=pytz.all_timezones.index("UTC"))
        current_time = datetime.datetime.now(pytz.timezone(timezone))
        issued_at_date = st.date_input("Issued At Date (iat)", current_time.date())
        issued_at_time = st.time_input("Issued At Time", current_time.time())
        expiration_type = st.radio("Expiration Type", ["Days", "Hours", "Minutes", "Custom Date"], horizontal=True)

        if expiration_type == "Days":
            expiration_value = st.number_input("Expiration (days from now)", min_value=1, value=7)
            expiration_delta = datetime.timedelta(days=expiration_value)
            expiration_datetime = datetime.datetime.combine(issued_at_date, issued_at_time) + expiration_delta
        elif expiration_type == "Hours":
            expiration_value = st.number_input("Expiration (hours from now)", min_value=1, value=24)
            expiration_delta = datetime.timedelta(hours=expiration_value)
            expiration_datetime = datetime.datetime.combine(issued_at_date, issued_at_time) + expiration_delta
        elif expiration_type == "Minutes":
            expiration_value = st.number_input("Expiration (minutes from now)", min_value=1, value=60)
            expiration_delta = datetime.timedelta(minutes=expiration_value)
            expiration_datetime = datetime.datetime.combine(issued_at_date, issued_at_time) + expiration_delta
        else:
            expiration_date = st.date_input("Expiration Date", current_time.date() + datetime.timedelta(days=7))
            expiration_time = st.time_input("Expiration Time", current_time.time())
            expiration_datetime = datetime.datetime.combine(expiration_date, expiration_time)

        local_tz = pytz.timezone(timezone)
        expiration_datetime = local_tz.localize(expiration_datetime)
        st.info(f"Token will expire on: {expiration_datetime.strftime('%Y-%m-%d %H:%M:%S %Z')}")

        include_nbf = st.checkbox("Include Not Before (nbf)", False)
        if include_nbf:
            nbf_date = st.date_input("Not Before Date", current_time.date())
            nbf_time = st.time_input("Not Before Time", current_time.time())
            nbf_datetime = datetime.datetime.combine(nbf_date, nbf_time)
            nbf_datetime = local_tz.localize(nbf_datetime)
        else:
            nbf_datetime = None

    st.markdown("---")
    st.subheader("Custom Claims (Optional)")
    custom_claims = st.text_area("Additional Claims (JSON format)", 
        value='{\n  "site": "example.com",\n  "custom_field": "custom_value"\n}', height=150)

    if st.button("Generate Token", type="primary", use_container_width=True):
        if not jwt_secret:
            st.error("Please provide a JWT Secret Key")
        else:
            try:
                additional_claims = {}
                if custom_claims:
                    additional_claims = json.loads(custom_claims)
                issued_datetime = local_tz.localize(datetime.datetime.combine(issued_at_date, issued_at_time))
                iat = int(issued_datetime.timestamp())
                exp = int(expiration_datetime.timestamp())
                payload = {
                    "iss": site_url,
                    "iat": iat,
                    "exp": exp,
                    "data": {
                        "user": {
                            "id": user_id,
                            "username": username,
                            "email": email,
                            "roles": user_roles
                        }
                    }
                }

                if include_nbf:
                    payload["nbf"] = int(nbf_datetime.timestamp())
                if include_jti:
                    payload["jti"] = str(uuid.uuid4())
                if include_aud:
                    payload["aud"] = audience

                payload.update(additional_claims)
                token = jwt.encode(payload, jwt_secret, algorithm=algorithm)

                st.success("Token successfully generated!")
                st.code(token, language='text')

            except Exception as e:
                st.error(f"An error occurred while generating the token: {e}")

with tab2:
    st.subheader("Token Validator")
    token_to_validate = st.text_area("Paste JWT Token Here", height=150)
    secret_for_validation = st.text_input("JWT Secret Key", type="password")
    algo_for_validation = st.selectbox("Algorithm Used", ["HS256", "HS384", "HS512"])

    if st.button("Validate Token"):
        if not token_to_validate or not secret_for_validation:
            st.error("Please provide both the token and the secret key")
        else:
            try:
                decoded = jwt.decode(token_to_validate, secret_for_validation, algorithms=[algo_for_validation])
                st.success("Token is valid!")
                st.json(decoded)
            except jwt.ExpiredSignatureError:
                st.error("The token has expired.")
            except jwt.InvalidTokenError as e:
                st.error(f"Invalid token: {e}")

with tab3:
    st.subheader("Documentation")
    st.markdown("""
    **Usage Guide**  
    1. Go to the **Token Generator** tab.  
    2. Fill in the required fields and configure your token as needed.  
    3. Click **Generate Token** to get your JWT.  
    4. Use this token with supported WordPress plugins for authentication.  
    5. Use the **Token Validator** to verify any token you receive.

    **Supported Plugin**  
    This works with [JWT Authentication for WP REST API](https://wordpress.org/plugins/jwt-authentication/).

    **Security Note**  
    Make sure to keep your JWT secret key safe and never expose it in frontend code or public repositories.
    """)

# Footer
st.markdown('<div class="footer">Made with ❤️ using Streamlit | © 2025</div>', unsafe_allow_html=True)
