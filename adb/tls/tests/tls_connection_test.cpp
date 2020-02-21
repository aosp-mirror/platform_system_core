/*
 * Copyright 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "AdbWifiTlsConnectionTest"

#include <thread>

#include <gtest/gtest.h>

#include <adb/crypto/rsa_2048_key.h>
#include <adb/crypto/x509_generator.h>
#include <adb/tls/adb_ca_list.h>
#include <adb/tls/tls_connection.h>
#include <android-base/logging.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <openssl/ssl.h>

using namespace adb::crypto;

namespace adb {
namespace tls {

using android::base::unique_fd;
using TlsError = TlsConnection::TlsError;

// Test X.509 certificates (RSA 2048)
static const std::string kTestRsa2048ServerCert =
        "-----BEGIN CERTIFICATE-----\n"
        "MIIDFzCCAf+gAwIBAgIBATANBgkqhkiG9w0BAQsFADAtMQswCQYDVQQGEwJVUzEQ\n"
        "MA4GA1UECgwHQW5kcm9pZDEMMAoGA1UEAwwDQWRiMB4XDTIwMDEyMTIyMjU1NVoX\n"
        "DTMwMDExODIyMjU1NVowLTELMAkGA1UEBhMCVVMxEDAOBgNVBAoMB0FuZHJvaWQx\n"
        "DDAKBgNVBAMMA0FkYjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK8E\n"
        "2Ck9TfuKlz7wqWdMfknjZ1luFDp2IHxAUZzh/F6jeI2dOFGAjpeloSnGOE86FIaT\n"
        "d1EvpyTh7nBwbrLZAA6XFZTo7Bl6BdNOQdqb2d2+cLEN0inFxqUIycevRtohUE1Y\n"
        "FHM9fg442X1jOTWXjDZWeiqFWo95paAPhzm6pWqfJK1+YKfT1LsWZpYqJGGQE5pi\n"
        "C3qOBYYgFpoXMxTYJNoZo3uOYEdM6upc8/vh15nMgIxX/ymJxEY5BHPpZPPWjXLg\n"
        "BfzVaV9fUfv0JT4HQ4t2WvxC3cD/UsjWp2a6p454uUp2ENrANa+jRdRJepepg9D2\n"
        "DKsx9L8zjc5Obqexrt0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8B\n"
        "Af8EBAMCAYYwHQYDVR0OBBYEFDFW+8GTErwoZN5Uu9KyY4QdGYKpMA0GCSqGSIb3\n"
        "DQEBCwUAA4IBAQBCDEn6SHXGlq5TU7J8cg1kRPd9bsJW+0hDuKSq0REXDkl0PcBf\n"
        "fy282Agg9enKPPKmnpeQjM1dmnxdM8tT8LIUbMl779i3fn6v9HJVB+yG4gmRFThW\n"
        "c+AGlBnrIT820cX/gU3h3R3FTahfsq+1rrSJkEgHyuC0HYeRyveSckBdaEOLvx0S\n"
        "toun+32JJl5hWydpUUZhE9Mbb3KHBRM2YYZZU9JeJ08Apjl+3lRUeMAUwI5fkAAu\n"
        "z/1SqnuGL96bd8P5ixdkA1+rF8FPhodGcq9mQOuUGP9g5HOXjaNoJYvwVRUdLeGh\n"
        "cP/ReOTwQIzM1K5a83p8cX8AGGYmM7dQp7ec\n"
        "-----END CERTIFICATE-----\n";

static const std::string kTestRsa2048ServerPrivKey =
        "-----BEGIN PRIVATE KEY-----\n"
        "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCvBNgpPU37ipc+\n"
        "8KlnTH5J42dZbhQ6diB8QFGc4fxeo3iNnThRgI6XpaEpxjhPOhSGk3dRL6ck4e5w\n"
        "cG6y2QAOlxWU6OwZegXTTkHam9ndvnCxDdIpxcalCMnHr0baIVBNWBRzPX4OONl9\n"
        "Yzk1l4w2VnoqhVqPeaWgD4c5uqVqnyStfmCn09S7FmaWKiRhkBOaYgt6jgWGIBaa\n"
        "FzMU2CTaGaN7jmBHTOrqXPP74deZzICMV/8picRGOQRz6WTz1o1y4AX81WlfX1H7\n"
        "9CU+B0OLdlr8Qt3A/1LI1qdmuqeOeLlKdhDawDWvo0XUSXqXqYPQ9gyrMfS/M43O\n"
        "Tm6nsa7dAgMBAAECggEAFCS2bPdUKIgjbzLgtHW+hT+J2hD20rcHdyAp+dNH/2vI\n"
        "yLfDJHJA4chGMRondKA704oDw2bSJxxlG9t83326lB35yxPhye7cM8fqgWrK8PVl\n"
        "tU22FhO1ZgeJvb9OeXWNxKZyDW9oOOJ8eazNXVMuEo+dFj7B6l3MXQyHJPL2mJDm\n"
        "u9ofFLdypX+gJncVO0oW0FNJnEUn2MMwHDNlo7gc4WdQuidPkuZItKRGcB8TTGF3\n"
        "Ka1/2taYdTQ4Aq//Z84LlFvE0zD3T4c8LwYYzOzD4gGGTXvft7vSHzIun1S8YLRS\n"
        "dEKXdVjtaFhgH3uUe4j+1b/vMvSHeoGBNX/G88GD+wKBgQDWUYVlMVqc9HD2IeYi\n"
        "EfBcNwAJFJkh51yAl5QbUBgFYgFJVkkS/EDxEGFPvEmI3/pAeQFHFY13BI466EPs\n"
        "o8Z8UUwWDp+Z1MFHHKQKnFakbsZbZlbqjJ9VJsqpezbpWhMHTOmcG0dmE7rf0lyM\n"
        "eQv9slBB8qp2NEUs5Of7f2C2bwKBgQDRDq4nUuMQF1hbjM05tGKSIwkobmGsLspv\n"
        "TMhkM7fq4RpbFHmbNgsFqMhcqYZ8gY6/scv5KCuAZ4yHUkbqwf5h+QCwrJ4uJeUJ\n"
        "ZgJfHus2mmcNSo8FwSkNoojIQtzcbJav7bs2K9VTuertk/i7IJLApU4FOZZ5pghN\n"
        "EXu0CZF1cwKBgDWFGhjRIF29tU/h20R60llU6s9Zs3wB+NmsALJpZ/ZAKS4VPB5f\n"
        "nCAXBRYSYRKrTCU5kpYbzb4BBzuysPOxWmnFK4j+keCqfrGxd02nCQP7HdHJVr8v\n"
        "6sIq88UrHeVcNxBFprjzHvtgxfQK5k22FMZ/9wbhAKyQFQ5HA5+MiaxFAoGAIcZZ\n"
        "ZIkDninnYIMS9OursShv5lRO+15j3i9tgKLKZ+wOMgDQ1L6acUOfezj4PU1BHr8+\n"
        "0PYocQpJreMhCfRlgLaV4fVBaPs+UZJld7CrF5tCYudUy/01ALrtlk0XGZWBktK5\n"
        "mDrksC4tQkzRtonAq9cJD9cJ9IVaefkFH0UcdvkCgYBpZj50VLeGhnHHBnkJRlV1\n"
        "fV+/P6PAq6RtqjA6O9Qdaoj5V3w2d63aQcQXQLJjH2BBmtCIy47r04rFvZpbCxP7\n"
        "NH/OnK9NHpk2ucRTe8TAnVbvF/TZzPJoIxAO/D3OWaW6df4R8en8u6GYzWFglAyT\n"
        "sydGT8yfWD1FYUWgfrVRbg==\n"
        "-----END PRIVATE KEY-----\n";

static const std::string kTestRsa2048ClientCert =
        "-----BEGIN CERTIFICATE-----\n"
        "MIIDFzCCAf+gAwIBAgIBATANBgkqhkiG9w0BAQsFADAtMQswCQYDVQQGEwJVUzEQ\n"
        "MA4GA1UECgwHQW5kcm9pZDEMMAoGA1UEAwwDQWRiMB4XDTIwMDEyMTIyMjU1NloX\n"
        "DTMwMDExODIyMjU1NlowLTELMAkGA1UEBhMCVVMxEDAOBgNVBAoMB0FuZHJvaWQx\n"
        "DDAKBgNVBAMMA0FkYjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAI3a\n"
        "EXh1S5FTbet7JVONswffRPaekdIK53cb8SnAbSO9X5OLA4zGwdkrBvDTsd96SKrp\n"
        "JxmoNOE1DhbZh05KPlWAPkGKacjGWaz+S7biDOL0I6aaLbTlU/il1Ub9olPSBVUx\n"
        "0nhdtEFgIOzddnP6/1KmyIIeRxS5lTKeg4avqUkZNXkz/wL1dHBFL7FNFf0SCcbo\n"
        "tsub/deFbjZ27LTDN+SIBgFttTNqC5NTvoBAoMdyCOAgNYwaHO+fKiK3edfJieaw\n"
        "7HD8qqmQxcpCtRlA8CUPj7GfR+WHiCJmlevhnkFXCo56R1BS0F4wuD4KPdSWt8gc\n"
        "27ejH/9/z2cKo/6SLJMCAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8B\n"
        "Af8EBAMCAYYwHQYDVR0OBBYEFO/Mr5ygqqpyU/EHM9v7RDvcqaOkMA0GCSqGSIb3\n"
        "DQEBCwUAA4IBAQAH33KMouzF2DYbjg90KDrDQr4rq3WfNb6P743knxdUFuvb+40U\n"
        "QjC2OJZHkSexH7wfG/y6ic7vfCfF4clNs3QvU1lEjOZC57St8Fk7mdNdsWLwxEMD\n"
        "uePFz0dvclSxNUHyCVMqNxddzQYzxiDWQRmXWrUBliMduQqEQelcxW2yDtg8bj+s\n"
        "aMpR1ra9scaD4jzIZIIxLoOS9zBMuNRbgP217sZrniyGMhzoI1pZ/izN4oXpyH7O\n"
        "THuaCzzRT3ph2f8EgmHSodz3ttgSf2DHzi/Ez1xUkk7NOlgNtmsxEdrM47+cC5ae\n"
        "fIf2V+1o1JW8J7D11RmRbNPh3vfisueB4f88\n"
        "-----END CERTIFICATE-----\n";

static const std::string kTestRsa2048ClientPrivKey =
        "-----BEGIN PRIVATE KEY-----\n"
        "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCN2hF4dUuRU23r\n"
        "eyVTjbMH30T2npHSCud3G/EpwG0jvV+TiwOMxsHZKwbw07Hfekiq6ScZqDThNQ4W\n"
        "2YdOSj5VgD5BimnIxlms/ku24gzi9COmmi205VP4pdVG/aJT0gVVMdJ4XbRBYCDs\n"
        "3XZz+v9SpsiCHkcUuZUynoOGr6lJGTV5M/8C9XRwRS+xTRX9EgnG6LbLm/3XhW42\n"
        "duy0wzfkiAYBbbUzaguTU76AQKDHcgjgIDWMGhzvnyoit3nXyYnmsOxw/KqpkMXK\n"
        "QrUZQPAlD4+xn0flh4giZpXr4Z5BVwqOekdQUtBeMLg+Cj3UlrfIHNu3ox//f89n\n"
        "CqP+kiyTAgMBAAECggEAAa64eP6ggCob1P3c73oayYPIbvRqiQdAFOrr7Vwu7zbr\n"
        "z0rde+n6RU0mrpc+4NuzyPMtrOGQiatLbidJB5Cx3z8U00ovqbCl7PtcgorOhFKe\n"
        "VEzihebCcYyQqbWQcKtpDMhOgBxRwFoXieJb6VGXfa96FAZalCWvXgOrTl7/BF2X\n"
        "qMqIm9nJi+yS5tIO8VdOsOmrMWRH/b/ENUcef4WpLoxTXr0EEgyKWraeZ/hhXo1e\n"
        "z29dZKqdr9wMsq11NPsRddwS94jnDkXTo+EQyWVTfB7gb6yyp07s8jysaDb21tVv\n"
        "UXB9MRhDV1mOv0ncXfXZ4/+4A2UahmZaLDAVLaat4QKBgQDAVRredhGRGl2Nkic3\n"
        "KvZCAfyxug788CgasBdEiouz19iCCwcgMIDwnq0s3/WM7h/laCamT2x38riYDnpq\n"
        "rkYMfuVtU9CjEL9pTrdfwbIRhTwYNqADaPz2mXwQUhRXutE5TIdgxxC/a+ZTh0qN\n"
        "S+vhTj/4hf0IZhMh5Nqj7IPExQKBgQC8zxEzhmSGjys0GuE6Wl6Doo2TpiR6vwvi\n"
        "xPLU9lmIz5eca/Rd/eERioFQqeoIWDLzx52DXuz6rUoQhbJWz9hP3yqCwXD+pbNP\n"
        "oDJqDDbCC4IMYEb0IK/PEPH+gIpnTjoFcW+ecKDFG7W5Lt05J8WsJsfOaJvMrOU+\n"
        "dLXq3IgxdwKBgQC5RAFq0v6e8G+3hFaEHL0z3igkpt3zJf7rnj37hx2FMmDa+3Z0\n"
        "umQp5B9af61PgL12xLmeMBmC/Wp1BlVDV/Yf6Uhk5Hyv5t0KuomHEtTNbbLyfAPs\n"
        "5P/vJu/L5NS1oT4S3LX3MineyjgGs+bLbpub3z1dzutrYLADUSiPCK/xJQKBgBQt\n"
        "nQ0Ao+Wtj1R2OvPdjJRM3wyUiPmFSWPm4HzaBx+T8AQLlYYmB9O0FbXlMtnJc0iS\n"
        "YMcVcgYoVu4FG9YjSF7g3s4yljzgwJUV7c1fmMqMKE3iTDLy+1cJ3JLycdgwiArk\n"
        "4KTyLHxkRbuQwpvFIF8RlfD9RQlOwQE3v+llwDhpAoGBAL6XG6Rp6mBoD2Ds5c9R\n"
        "943yYgSUes3ji1SI9zFqeJtj8Ml/enuK1xu+8E/BxB0//+vgZsH6i3i8GFwygKey\n"
        "CGJF8CbiHc3EJc3NQIIRXcni/CGacf0HwC6m+PGFDBIpA4H2iDpVvCSofxttQiq0\n"
        "/Z7HXmXUvZHVyYi/QzX2Gahj\n"
        "-----END PRIVATE KEY-----\n";

static const std::string kTestRsa2048UnknownPrivKey =
        "-----BEGIN PRIVATE KEY-----\n"
        "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCrIhr+CS+6UI0w\n"
        "CTaVzQAicKBe6X531LeQAGYx7j5RLHR1QIoJ0WCc5msmXKe2VzcWuLbVdTGAIP1H\n"
        "mwbPqlbO4ioxeJhiDv+WPuLG8+j4Iw1Yqxt8cfohxjfvNmIQM8aF5hGyyaaTetDF\n"
        "EYWONoYCBC4WnFWgYCPb8mzWXlhHE3F66GnHpc32zydPTg3ZurGvSsFf7fNY9yRw\n"
        "8WtwPiI6mpRxt+n2bQUp+LZ+g/3rXLFPg8uWDGYG7IvLluWc9gR9lxjL64t6ryLU\n"
        "2cm7eTfDgLw/B1F/wEgCJDnby1JgQ4rq6klJO3BR2ooUr/7T343y5njG5hQJreV7\n"
        "5ZnSmRLZAgMBAAECggEABPrfeHZFuWkj7KqN+DbAmt/2aMCodZ3+7/20+528WkIe\n"
        "CvXzdmTth+9UHagLWNzpnVuHdYd9JuZ+3F00aelh8JAIDIu++naHhUSj9ohtRoBF\n"
        "oIeNK5ZJAj/Zi5hkauaIz8dxyyc/VdIYfm2bundXd7pNqYqH2tyFWp6PwH67GKlZ\n"
        "1lC7o8gKAK8sz9g0Ctdoe+hDqAsvYFCW4EWDM2qboucSgn8g3E/Gux/KrpXVv7d0\n"
        "PMQ60m+dyTOCMGqXIoDR3TAvQR7ex5sQ/QZSREdxKy878s/2FY4ktxtCUWlhrmcI\n"
        "VKtrDOGEKwNoiMluf2635rsVq2e01XhQlmdxbRFU0QKBgQDjOhhD1m9duFTQ2b+J\n"
        "Xfn6m8Rs7sZqO4Az7gLOWmD/vYWlK4n2nZsh6u5/cB1N+PA+ncvvV4yKJAlLHxbT\n"
        "pVvfzJ/jbUsj/NJg/w7+KYC9gXgRmBonuG2gRZF/5Otdlza4vMcoSkqGjlGxJyzL\n"
        "+9umEziN3tEYMRwipYvt7BgbUQKBgQDAzaXryJ3YD3jpecy/+fSnQvFjpyeDRqU1\n"
        "KDA9nxN5tJN6bnKhUlMhy64SsgvVX9jUuN7cK+qYV0uzdBn6kIAJNLWTdbtH93+e\n"
        "vNVgluR3jmixW4QfY9vfZKdXZbVGNc0DFMi1vJqgxTgQ5Mq5PxxxRL4FsAF840V1\n"
        "Wu9uhU0NCQKBgBfjga2QG8E0oeYbHmHouWE5gxsYt09v1fifqzfalJwOZsCIpUaC\n"
        "J08Xjd9kABC0fT14BXqyL5pOU5PMPvAdUF1k++JDGUU9TTjZV9AsuNYziFYBMa6/\n"
        "WvcgmT1i6cO7JAuj/SQlO1SOHdSME8+WOO9q0eVIaZ8repPB58YprhchAoGBAJyR\n"
        "Y8AJdkTSq7nNszvi245IioYGY8vzPo3gSOyBlesrfOfbcTMYC3JSWNXNyFZKM2br\n"
        "ie75qtRzb4IXMlGLrq3LI/jPjnpuvjBF4HFDl9yOxO3iB3UGPrM2pb4PVhnh7s4l\n"
        "vqf2tQsBnPn7EbVFTu+ch0NPHqYwWWNnqS/zCBMhAoGBAIkYjOE0iD9W2FXee6VL\n"
        "iN8wDqlqsGEEtLvykIDmTmM+ZX5ftQuPo18khpE9wQKmJ5OpoVTYIP1UsJFBakgo\n"
        "+dGaf6xVuPvmydNFqixlW3z227n4Px6GX7CXlCaAleTeItezli+dWf/9astwTA3x\n"
        "IazYzsxUUpZFC4dJ1GhBn3y1\n"
        "-----END PRIVATE KEY-----\n";

static const std::string kTestRsa2048UnknownCert =
        "-----BEGIN CERTIFICATE-----\n"
        "MIIDFzCCAf+gAwIBAgIBATANBgkqhkiG9w0BAQsFADAtMQswCQYDVQQGEwJVUzEQ\n"
        "MA4GA1UECgwHQW5kcm9pZDEMMAoGA1UEAwwDQWRiMB4XDTIwMDEyNDE4MzMwNVoX\n"
        "DTMwMDEyMTE4MzMwNVowLTELMAkGA1UEBhMCVVMxEDAOBgNVBAoMB0FuZHJvaWQx\n"
        "DDAKBgNVBAMMA0FkYjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKsi\n"
        "Gv4JL7pQjTAJNpXNACJwoF7pfnfUt5AAZjHuPlEsdHVAignRYJzmayZcp7ZXNxa4\n"
        "ttV1MYAg/UebBs+qVs7iKjF4mGIO/5Y+4sbz6PgjDVirG3xx+iHGN+82YhAzxoXm\n"
        "EbLJppN60MURhY42hgIELhacVaBgI9vybNZeWEcTcXroacelzfbPJ09ODdm6sa9K\n"
        "wV/t81j3JHDxa3A+IjqalHG36fZtBSn4tn6D/etcsU+Dy5YMZgbsi8uW5Zz2BH2X\n"
        "GMvri3qvItTZybt5N8OAvD8HUX/ASAIkOdvLUmBDiurqSUk7cFHaihSv/tPfjfLm\n"
        "eMbmFAmt5XvlmdKZEtkCAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8B\n"
        "Af8EBAMCAYYwHQYDVR0OBBYEFDtRSOm1ilhnq6bKN4qJ1ekK/PAkMA0GCSqGSIb3\n"
        "DQEBCwUAA4IBAQAP6Q8/OxnBA3BO8oxKer0tjI4rZMefUhbAKUWXYjTTNEBm5//b\n"
        "lVGP2RptO7bxj8w1L3rxsjmVcv2TqBOhrbJqvGVPE2ntoYlFhBBkRvmxuu1y5W9V\n"
        "uJU7SF9lNmDXShTURULu3P8GdeT1HGeXzWQ4x7VhY9a3VIbmN5VxjB+3C6hYZxSs\n"
        "DCpmidu/sR+n5Azlh6oqrhOxmv17PuF/ioTUsHd4y2Z41IvvO47oghxNDtboUUsg\n"
        "LfsM1MOxVC9PqOfQphFU4i8owNIYzBMadDLw+1TSQj0ALqZVyc9Dq+WDFdz+JAE+\n"
        "k7TkVU06UPGVSnLVzJeYwGCXQp3apBszY9vO\n"
        "-----END CERTIFICATE-----\n";

struct CAIssuerField {
    int nid;
    std::vector<uint8_t> val;
};
using CAIssuer = std::vector<CAIssuerField>;
static std::vector<CAIssuer> kCAIssuers = {
        {
                {NID_commonName, {'a', 'b', 'c', 'd', 'e'}},
                {NID_organizationName, {'d', 'e', 'f', 'g'}},
        },
        {
                {NID_commonName, {'h', 'i', 'j', 'k', 'l', 'm'}},
                {NID_countryName, {'n', 'o'}},
        },
};

class AdbWifiTlsConnectionTest : public testing::Test {
  protected:
    virtual void SetUp() override {
        android::base::Socketpair(SOCK_STREAM, &server_fd_, &client_fd_);
        server_ = TlsConnection::Create(TlsConnection::Role::Server, kTestRsa2048ServerCert,
                                        kTestRsa2048ServerPrivKey, server_fd_);
        client_ = TlsConnection::Create(TlsConnection::Role::Client, kTestRsa2048ClientCert,
                                        kTestRsa2048ClientPrivKey, client_fd_);
        ASSERT_NE(nullptr, server_);
        ASSERT_NE(nullptr, client_);
    }

    virtual void TearDown() override {
        WaitForClientConnection();
        // Shutdown the SSL connection first.
        server_.reset();
        client_.reset();
    }

    bssl::UniquePtr<STACK_OF(X509_NAME)> GetCAIssuerList() {
        bssl::UniquePtr<STACK_OF(X509_NAME)> ret(sk_X509_NAME_new_null());
        for (auto& issuer : kCAIssuers) {
            bssl::UniquePtr<X509_NAME> name(X509_NAME_new());
            for (auto& attr : issuer) {
                CHECK(X509_NAME_add_entry_by_NID(name.get(), attr.nid, MBSTRING_ASC,
                                                 attr.val.data(), attr.val.size(), -1, 0));
            }

            CHECK(bssl::PushToStack(ret.get(), std::move(name)));
        }

        return ret;
    }

    void StartClientHandshakeAsync(TlsError expected) {
        client_thread_ = std::thread([=]() { EXPECT_EQ(client_->DoHandshake(), expected); });
    }

    void WaitForClientConnection() {
        if (client_thread_.joinable()) {
            client_thread_.join();
        }
    }

    unique_fd server_fd_;
    unique_fd client_fd_;
    const std::vector<uint8_t> msg_{0xff, 0xab, 0x32, 0xf6, 0x12, 0x56};
    std::unique_ptr<TlsConnection> server_;
    std::unique_ptr<TlsConnection> client_;
    std::thread client_thread_;
};

TEST_F(AdbWifiTlsConnectionTest, InvalidCreationParams) {
    // Verify that passing empty certificate/private key results in a crash.
    ASSERT_DEATH(
            {
                server_ = TlsConnection::Create(TlsConnection::Role::Server, "",
                                                kTestRsa2048ServerPrivKey, server_fd_);
            },
            "");
    ASSERT_DEATH(
            {
                server_ = TlsConnection::Create(TlsConnection::Role::Server, kTestRsa2048ServerCert,
                                                "", server_fd_);
            },
            "");
    ASSERT_DEATH(
            {
                client_ = TlsConnection::Create(TlsConnection::Role::Client, "",
                                                kTestRsa2048ClientPrivKey, client_fd_);
            },
            "");
    ASSERT_DEATH(
            {
                client_ = TlsConnection::Create(TlsConnection::Role::Client, kTestRsa2048ClientCert,
                                                "", client_fd_);
            },
            "");
}

TEST_F(AdbWifiTlsConnectionTest, NoCertificateVerification) {
    // Allow any certificate
    server_->SetCertVerifyCallback([](X509_STORE_CTX*) { return 1; });
    client_->SetCertVerifyCallback([](X509_STORE_CTX*) { return 1; });
    StartClientHandshakeAsync(TlsError::Success);

    // Handshake should succeed
    ASSERT_EQ(server_->DoHandshake(), TlsError::Success);
    WaitForClientConnection();

    // Test client/server read and writes
    client_thread_ = std::thread([&]() {
        EXPECT_TRUE(client_->WriteFully(
                std::string_view(reinterpret_cast<const char*>(msg_.data()), msg_.size())));
        // Try with overloaded ReadFully
        std::vector<uint8_t> buf(msg_.size());
        ASSERT_TRUE(client_->ReadFully(buf.data(), msg_.size()));
        EXPECT_EQ(buf, msg_);
    });

    auto data = server_->ReadFully(msg_.size());
    EXPECT_EQ(data, msg_);
    EXPECT_TRUE(server_->WriteFully(
            std::string_view(reinterpret_cast<const char*>(msg_.data()), msg_.size())));

    WaitForClientConnection();
}

TEST_F(AdbWifiTlsConnectionTest, NoTrustedCertificates) {
    StartClientHandshakeAsync(TlsError::CertificateRejected);

    // Handshake should not succeed
    ASSERT_EQ(server_->DoHandshake(), TlsError::PeerRejectedCertificate);
    WaitForClientConnection();

    // All writes and reads should fail
    client_thread_ = std::thread([&]() {
        // Client write, server read should fail
        EXPECT_FALSE(client_->WriteFully(
                std::string_view(reinterpret_cast<const char*>(msg_.data()), msg_.size())));
        auto data = client_->ReadFully(msg_.size());
        EXPECT_EQ(data.size(), 0);
    });

    auto data = server_->ReadFully(msg_.size());
    EXPECT_EQ(data.size(), 0);
    EXPECT_FALSE(server_->WriteFully(
            std::string_view(reinterpret_cast<const char*>(msg_.data()), msg_.size())));

    WaitForClientConnection();
}

TEST_F(AdbWifiTlsConnectionTest, AddTrustedCertificates) {
    // Add peer certificates
    EXPECT_TRUE(client_->AddTrustedCertificate(kTestRsa2048ServerCert));
    EXPECT_TRUE(server_->AddTrustedCertificate(kTestRsa2048ClientCert));

    StartClientHandshakeAsync(TlsError::Success);

    // Handshake should succeed
    ASSERT_EQ(server_->DoHandshake(), TlsError::Success);
    WaitForClientConnection();

    // All read writes should succeed
    client_thread_ = std::thread([&]() {
        EXPECT_TRUE(client_->WriteFully(
                std::string_view(reinterpret_cast<const char*>(msg_.data()), msg_.size())));
        auto data = client_->ReadFully(msg_.size());
        EXPECT_EQ(data, msg_);
    });

    auto data = server_->ReadFully(msg_.size());
    EXPECT_EQ(data, msg_);
    EXPECT_TRUE(server_->WriteFully(
            std::string_view(reinterpret_cast<const char*>(msg_.data()), msg_.size())));

    WaitForClientConnection();
}

TEST_F(AdbWifiTlsConnectionTest, AddTrustedCertificates_ClientWrongCert) {
    // Server trusts a certificate, client has the wrong certificate
    EXPECT_TRUE(server_->AddTrustedCertificate(kTestRsa2048UnknownCert));
    // Client accepts any certificate
    client_->SetCertVerifyCallback([](X509_STORE_CTX*) { return 1; });

    // Without enabling EnableClientPostHandshakeCheck(), DoHandshake() will
    // succeed, because in TLS 1.3, the client doesn't get notified if the
    // server rejected the certificate until a read operation is called.
    StartClientHandshakeAsync(TlsError::Success);

    // Handshake should fail for server, succeed for client
    ASSERT_EQ(server_->DoHandshake(), TlsError::CertificateRejected);
    WaitForClientConnection();

    // Client writes will succeed, everything else will fail.
    client_thread_ = std::thread([&]() {
        EXPECT_TRUE(client_->WriteFully(
                std::string_view(reinterpret_cast<const char*>(msg_.data()), msg_.size())));
        auto data = client_->ReadFully(msg_.size());
        EXPECT_EQ(data.size(), 0);
    });

    auto data = server_->ReadFully(msg_.size());
    EXPECT_EQ(data.size(), 0);
    EXPECT_FALSE(server_->WriteFully(
            std::string_view(reinterpret_cast<const char*>(msg_.data()), msg_.size())));

    WaitForClientConnection();
}

TEST_F(AdbWifiTlsConnectionTest, ExportKeyingMaterial) {
    // Allow any certificate
    server_->SetCertVerifyCallback([](X509_STORE_CTX*) { return 1; });
    client_->SetCertVerifyCallback([](X509_STORE_CTX*) { return 1; });

    // Add peer certificates
    EXPECT_TRUE(client_->AddTrustedCertificate(kTestRsa2048ServerCert));
    EXPECT_TRUE(server_->AddTrustedCertificate(kTestRsa2048ClientCert));

    StartClientHandshakeAsync(TlsError::Success);

    // Handshake should succeed
    ASSERT_EQ(server_->DoHandshake(), TlsError::Success);
    WaitForClientConnection();

    // Verify the client and server's exported key material match.
    const size_t key_size = 64;
    auto client_key_material = client_->ExportKeyingMaterial(key_size);
    ASSERT_FALSE(client_key_material.empty());
    auto server_key_material = server_->ExportKeyingMaterial(key_size);
    ASSERT_TRUE(!server_key_material.empty());
    ASSERT_EQ(client_key_material.size(), key_size);
    ASSERT_EQ(client_key_material, server_key_material);
}

TEST_F(AdbWifiTlsConnectionTest, SetCertVerifyCallback_ClientAcceptsServerRejects) {
    // Client accepts all
    client_->SetCertVerifyCallback([](X509_STORE_CTX*) { return 1; });
    // Server rejects all
    server_->SetCertVerifyCallback([](X509_STORE_CTX*) { return 0; });
    // Client handshake should succeed, because in TLS 1.3, client does not
    // realize that the peer rejected the certificate until after a read
    // operation.
    StartClientHandshakeAsync(TlsError::Success);

    // Server handshake should fail
    ASSERT_EQ(server_->DoHandshake(), TlsError::CertificateRejected);
    WaitForClientConnection();
}

TEST_F(AdbWifiTlsConnectionTest, SetCertVerifyCallback_ClientAcceptsServerRejects_PostHSCheck) {
    // Client accepts all
    client_->SetCertVerifyCallback([](X509_STORE_CTX*) { return 1; });
    // Client should now get a failure in the handshake
    client_->EnableClientPostHandshakeCheck(true);
    // Server rejects all
    server_->SetCertVerifyCallback([](X509_STORE_CTX*) { return 0; });

    // Client handshake should fail because server rejects everything
    StartClientHandshakeAsync(TlsError::PeerRejectedCertificate);

    // Server handshake should fail
    ASSERT_EQ(server_->DoHandshake(), TlsError::CertificateRejected);
    WaitForClientConnection();
}

TEST_F(AdbWifiTlsConnectionTest, SetCertVerifyCallback_ClientRejectsServerAccepts) {
    // Client rejects all
    client_->SetCertVerifyCallback([](X509_STORE_CTX*) { return 0; });
    // Server accepts all
    server_->SetCertVerifyCallback([](X509_STORE_CTX*) { return 1; });
    // Client handshake should fail
    StartClientHandshakeAsync(TlsError::CertificateRejected);

    // Server handshake should fail
    ASSERT_EQ(server_->DoHandshake(), TlsError::PeerRejectedCertificate);
    WaitForClientConnection();
}

TEST_F(AdbWifiTlsConnectionTest, SetCertVerifyCallback_ClientRejectsServerAccepts_PostHSCheck) {
    // Client rejects all
    client_->SetCertVerifyCallback([](X509_STORE_CTX*) { return 0; });
    // This shouldn't affect the error types returned in the
    // #SetCertVerifyCallback_ClientRejectsServerAccepts test, since
    // the failure is still within the TLS 1.3 handshake.
    client_->EnableClientPostHandshakeCheck(true);
    // Server accepts all
    server_->SetCertVerifyCallback([](X509_STORE_CTX*) { return 1; });

    // Client handshake should fail
    StartClientHandshakeAsync(TlsError::CertificateRejected);

    // Server handshake should fail
    ASSERT_EQ(server_->DoHandshake(), TlsError::PeerRejectedCertificate);
    WaitForClientConnection();
}

TEST_F(AdbWifiTlsConnectionTest, EnableClientPostHandshakeCheck_ClientWrongCert) {
    client_->AddTrustedCertificate(kTestRsa2048ServerCert);
    // client's DoHandshake() will fail if the server rejected the certificate
    client_->EnableClientPostHandshakeCheck(true);

    // Add peer certificates
    EXPECT_TRUE(server_->AddTrustedCertificate(kTestRsa2048UnknownCert));

    // Handshake should fail for client
    StartClientHandshakeAsync(TlsError::PeerRejectedCertificate);

    // Handshake should fail for server
    ASSERT_EQ(server_->DoHandshake(), TlsError::CertificateRejected);
    WaitForClientConnection();

    // All read writes should fail
    client_thread_ = std::thread([&]() {
        EXPECT_FALSE(client_->WriteFully(
                std::string_view(reinterpret_cast<const char*>(msg_.data()), msg_.size())));
        auto data = client_->ReadFully(msg_.size());
        EXPECT_EQ(data.size(), 0);
    });

    auto data = server_->ReadFully(msg_.size());
    EXPECT_EQ(data.size(), 0);
    EXPECT_FALSE(server_->WriteFully(
            std::string_view(reinterpret_cast<const char*>(msg_.data()), msg_.size())));

    WaitForClientConnection();
}

TEST_F(AdbWifiTlsConnectionTest, SetClientCAList_Empty) {
    // Setting an empty CA list should not crash
    server_->SetClientCAList(nullptr);
    ASSERT_DEATH(
            {
                // Client cannot use this API
                client_->SetClientCAList(nullptr);
            },
            "");
}

TEST_F(AdbWifiTlsConnectionTest, SetClientCAList_Smoke) {
    auto bsslIssuerList = GetCAIssuerList();
    server_->SetClientCAList(bsslIssuerList.get());
    client_->SetCertVerifyCallback([](X509_STORE_CTX*) { return 1; });

    client_thread_ = std::thread([&]() {
        client_->SetCertificateCallback([&](SSL* ssl) -> int {
            const STACK_OF(X509_NAME)* received = SSL_get_client_CA_list(ssl);
            EXPECT_NE(received, nullptr);
            const size_t num_names = sk_X509_NAME_num(received);
            EXPECT_EQ(kCAIssuers.size(), num_names);

            // Client initially registered with the wrong key. Let's change it
            // here to verify this callback actually changes the client
            // certificate to the right one.
            EXPECT_TRUE(TlsConnection::SetCertAndKey(ssl, kTestRsa2048UnknownCert,
                                                     kTestRsa2048UnknownPrivKey));

            const size_t buf_size = 256;
            uint8_t buf[buf_size];
            size_t idx = 0;
            for (auto& issuer : kCAIssuers) {
                auto* name = sk_X509_NAME_value(received, idx++);
                for (auto& attr : issuer) {
                    EXPECT_EQ(X509_NAME_get_text_by_NID(name, attr.nid,
                                                        reinterpret_cast<char*>(buf), buf_size),
                              attr.val.size());
                    std::vector<uint8_t> out(buf, buf + attr.val.size());
                    EXPECT_EQ(out, attr.val);
                }
            }

            return 1;
        });
        // Client handshake should succeed
        ASSERT_EQ(client_->DoHandshake(), TlsError::Success);
    });

    EXPECT_TRUE(server_->AddTrustedCertificate(kTestRsa2048UnknownCert));
    // Server handshake should succeed
    ASSERT_EQ(server_->DoHandshake(), TlsError::Success);
    client_thread_.join();
}

TEST_F(AdbWifiTlsConnectionTest, SetClientCAList_AdbCAList) {
    bssl::UniquePtr<STACK_OF(X509_NAME)> ca_list(sk_X509_NAME_new_null());
    std::string keyhash = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    auto issuer = CreateCAIssuerFromEncodedKey(keyhash);
    ASSERT_TRUE(bssl::PushToStack(ca_list.get(), std::move(issuer)));
    server_->SetClientCAList(ca_list.get());
    client_->SetCertVerifyCallback([](X509_STORE_CTX*) { return 1; });

    client_thread_ = std::thread([&]() {
        client_->SetCertificateCallback([&](SSL* ssl) -> int {
            // Client initially registered with a certificate that is not trusted by
            // the server. Let's test that we can change the certificate to the
            // trusted one here.
            const STACK_OF(X509_NAME)* received = SSL_get_client_CA_list(ssl);
            EXPECT_NE(received, nullptr);
            const size_t num_names = sk_X509_NAME_num(received);
            EXPECT_EQ(1, num_names);

            auto* name = sk_X509_NAME_value(received, 0);
            EXPECT_NE(name, nullptr);
            auto enc_key = ParseEncodedKeyFromCAIssuer(name);
            EXPECT_EQ(keyhash, enc_key);

            return 1;
        });
        // Client handshake should succeed
        ASSERT_EQ(client_->DoHandshake(), TlsError::Success);
    });

    server_->SetCertVerifyCallback([](X509_STORE_CTX*) { return 1; });
    // Server handshake should succeed
    ASSERT_EQ(server_->DoHandshake(), TlsError::Success);
    client_thread_.join();
}
}  // namespace tls
}  // namespace adb
