#!/bin/bash

# Asumption: If opendj installation fails, it fails opendj package.
#            If replication configuration fails, it does not fail opendj package
# Only configure replication during an install ($1 = 1)  and not during an upgrade ($1 = 2)


if [ -f /opt/ericsson/com.ericsson.oss.security/idenmgmt/opendj/bin/bintools.sh ]; then
    . /opt/ericsson/com.ericsson.oss.security/idenmgmt/opendj/bin/bintools.sh
fi




LOGGER_TAG="ENM_CERT_CONFIG"
OPENSSL=/usr/bin/openssl
SHARE_ROOT=/ericsson/tor/data
CERTS_DIR=/opt/ericsson/com.ericsson.oss.security/idenmgmt/opendj/certs
GLOBAL_PROPERTIES="${SHARE_ROOT}/global.properties"
CERTIFICATES_DIR=${SHARE_ROOT}/certificates/sso
KEY_VALIDITY_PERIOD=7300    # set validity period for ssl key to 20 years
APACHE_KEY_CERT_NAME=ssoserverapache
JBOSS_KEY_CERT_NAME=ssoserverjboss
SSL_CONFIG=/var/tmp/sslconfig.cnf

info()
{
    echo "$@"
    logger -s -t IDENMGMT_OPENDJ -p user.notice "INFORMATION ( ${LOGGER_TAG} ): $@"
}

error()
{
    echo "$@"
    logger -s -t IDENMGMT_OPENDJ -p user.err "ERROR ( ${LOGGER_TAG} ): $@"
}

generate_ssl_options() {

    # Create the temporary SSL config file
    cat << EOT > ${SSL_CONFIG}
[ req ]
distinguished_name  = req_distinguished_name
x509_extensions     = v3_ca_req

[ req_distinguished_name ]

[ v3_ca_req ]
basicConstraints=CA:FALSE
EOT

}

generate_certs()
{
    ${OPENSSL} req \
        -nodes \
        -sha256 \
        -newkey rsa:2048 \
        -keyout ${CERTIFICATES_DIR}/${1}.key \
        -out ${CERTIFICATES_DIR}/${1}.csr \
        -subj "/O=SSO/CN=${2}" \
        -extensions v3_ca_req \
        -config ${SSL_CONFIG}

    [ $? -ne 0 ] && info "Failed to create ${CERTIFICATES_DIR}/${1}.csr, continuing anyway"

    ${OPENSSL} x509 \
        -req \
        -days 365 \
        -in ${CERTIFICATES_DIR}/${1}.csr \
        -signkey ${CERTIFICATES_DIR}/${1}.key \
        -out ${CERTIFICATES_DIR}/${1}.crt

    [ $? -ne 0 ] && info "Failed to create ${CERTIFICATES_DIR}/${1}.crt, continuing anyway"

    ${RM} -f ${CERTIFICATES_DIR}/${1}.csr
}

graceful_exit ()
{
    [ "${#}" -gt 1 -a "${1}" -eq 0 ] && info "${2}"
    [ "${#}" -gt 1 -a "${1}" -gt 0 ] && error "${2}"
    exit ${1}
}

# Main
# Source global.properties file

    . ${GLOBAL_PROPERTIES}

    if [ ! -f "${SHARE_ROOT}/certificates/rootCA.pem" ]; then
      info "Copying certificates"
      mkdir ${SHARE_ROOT}/certificates
      cp -R ${CERTS_DIR}/certificates/* ${SHARE_ROOT}/certificates
      [ ${?} -ne 0 ] && info "Problem with copying certificates, continuing anyway"
    fi

    # This modification is due to the requirement to remove passkey files from opendj repo only for Physical deployment.

    if [ "${DDC_ON_CLOUD}" == TRUE ] || [ "${cENM_DEPLOYMENT}" == TRUE ] ; then
        mkdir ${SHARE_ROOT}/idenmgmt
        info "Copying keys to ${SHARE_ROOT}/idenmgmt"
        cp -R ${CERTS_DIR}/idenmgmt/* ${SHARE_ROOT}/idenmgmt
        [ ${?} -ne 0 ] && info "Problem with copying keys, continuing anyway"
    else # we are on pENM
        info "Removing passkeys from source folder ${CERTS_DIR}/idenmgmt/"
        rm -f ${CERTS_DIR}/idenmgmt/*
    fi


    if [ "${DDC_ON_CLOUD}" == TRUE ] || [ "${cENM_DEPLOYMENT}" == TRUE ] ; then
        info "Assure 755 permissions for ${SHARE_ROOT}/idenmgmt folders"
        chmod 755 ${SHARE_ROOT}/idenmgmt
    fi

    info "Assure 755 permissions for ${SHARE_ROOT}/certificates folders"
    chmod 755 ${SHARE_ROOT}/certificates
    info "Generating certificates"
    generate_ssl_options
    generate_certs ${APACHE_KEY_CERT_NAME} ${UI_PRES_SERVER}
    generate_certs ${JBOSS_KEY_CERT_NAME} sso.${UI_PRES_SERVER}
    ${RM} -f ${SSL_CONFIG}

exit 0
