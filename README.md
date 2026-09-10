# Step Posture Connector

Step Posture Connector (`step-posture-connector`) is a middleware tool designed to assist [`step-ca`](https://github.com/smallstep/certificates) with posture information during an ACME device attestation process.

It was originally born to leverage [Managed Device Attestation for Apple devices](https://support.apple.com/en-au/guide/deployment/dep28afbde6a/web) in a [`step-ca`](https://github.com/smallstep/certificates) and Jamf Pro environment as a control to ensure that Apple attested ACME certificates are securely issued to approved, managed and compliant devices. It also supports flat files (JSON, CSV) and Mosyle Business/Manager, and plans to incorporate other MDM providers such as Intune and Kandji.

Step Posture Connector utilises the [webhooks](https://smallstep.com/docs/step-ca/webhooks/) functionality within [`step-ca`](https://github.com/smallstep/certificates) to allow/deny and enrich certificates with additional data during the order process.

This project is licensed under the [terms of the MIT license](LICENSE).

*Note that whilst this open source tool is designed to work with `step-ca`, it is not supported or endorsed by [Smallstep](https://smallstep.com/) or the team behind `step-ca`.*

## Protection of the device-attest-01 challenge

The `device-attest-01` ACME challenge can pose significant a security risk in production when exposed to the internet without further additional controls in place. Without external account binding or another authorisation method, any device that can satisfy the `device-attest-01` challenge can enroll in your PKI simply by knowing the ACME directory URI. In the case of Apple's Managed Device Attestation – when Apple provides attestation for a device, they are attesting that is is a genuine Apple device with specific identifiers, but not that it belongs to or is assigned to your organisation. Step Posture Connector helps you gatekeep this in a few ways:

- Attested permanent identifiers (UDIDs & serial numbers - see below) are matched against device records to authorise them as a managed device
- Lookups can return enriched data about devices and users that can be included in and further validated by logic within your [`step-ca`](https://github.com/smallstep/certificates) templates
- Optionally; devices can also be required to have membership of a specific compliance group within MDM. In the case of Jamf smart groups, this can be used to require up to date inventory check-in, OS versions, or any other attribute to to gatekeep certificate issuance - see [Compliance Group Membership](https://github.com/jedda/step-posture-connector#compliance-group-membership) below.

See [Usage Philosophy & Considerations](https://github.com/jedda/step-posture-connector#usage-philosophy--considerations) below for more details on using `step-posture-connector` to secure resources or services.

## Providers

Below is the list of currently supported providers and  a brief explanation of what they do:

| Provider | Description |
| --- | ----------- |
| `file` | Reads a local file (JSON, CSV) with device identifiers and optional enrichment data and matches device requests against this list. Great for testing or gatekeeping against a specific static list of devices. |
| `jamf` | Uses the Jamf API to match device identifiers against an enrolled Mobile Device or Computer. Can use an optional compliance group to gatekeep a subset of devices and can return enrichment data. |
| `mosyle` | Uses the Mosyle Business/Manager API to match device identifiers across all device types (iOS, iPadOS, macOS, tvOS). Can require one or more compliance tags and can return enrichment data. |

Ideally, next steps will include addition of new providers for posture & data enrichment. Happy to take feedback, but would suggest Intune, Kandji & Addigy as logical next steps.

## Security

`step-posture-connector` supports the following to ensure a secure connection between itself and [`step-ca`](https://github.com/smallstep/certificates):

- TLS version enforcement (v1.2 & above) and modern, secure server cipher suite selection
- HMAC verification of Smallstep request via provided [`step-ca`](https://github.com/smallstep/certificates) headers
- Optional mutual TLS via client certificate verification from [`step-ca`](https://github.com/smallstep/certificates)

## Getting started

I've started creating a [Setup Guide](https://github.com/jedda/step-posture-connector/wiki/Setup-Guide) which should walk you through the steps of setting up `step-posture-connector` and starting to lookup and authorise attested devices. It's currently a little rough around the edges, but should be enough to get you started.

If you'd like to report any security issues, [send me a DM on the MacAdmins slack](https://macadmins.slack.com/team/U1QABUHAR).

## Deployment

### Docker image (reccomended)

Deployment via Docker is probably most simple and reccomended - particularly if you are already [running `step-ca` this way](https://hub.docker.com/r/smallstep/step-ca). All config can be done via environment variables as per the Configuration section below and a [docker-compose file](docker/docker-compose.yml) is included in this repository.

Releases of `step-posture-connector` [are available on Docker Hub as `jedda/step-posture-connector`](https://hub.docker.com/repository/docker/jedda/step-posture-connector).

### Standalone binaries

You can run `step-posture-connector` as a standalone binary. When doing so, configuration is easiest via a .env file in it's working directory or via standard environment variables as per the Configuration section below.

Releases are [available for major platforms as compiled binaries here](https://github.com/jedda/step-posture-connector/releases).

### Building `step-posture-connector`

You can of course choose to download and build your own binaries or docker containers. `step-posture-connector` is [written in Go](https://go.dev/project) and can be run with a simple `go run main.go`.

A [Dockerfile](docker/Dockerfile) is also included should you wish to roll your own container variants.

## Webhooks

`step-posture-connector` exposes two webhook endpoints, one per kind of request. Which one you
point a provisioner's webhook at is what tells `step-posture-connector` - and forces, on the
`step-ca` side - whether that request is validated as an ACME device attestation or a SCEP
challenge:

- `/webhook/device-attest` for a provisioner's ACME (`device-attest-01`) `AUTHORIZING` or
  `ENRICHING` webhook
- `/webhook/scep-challenge` for a SCEP provisioner's `SCEPCHALLENGE` webhook (see "SCEP challenge
  webhooks" below)

For each webhook you create in [`step-ca`](https://github.com/smallstep/certificates), it will generate and display a `Webhook ID` and `Webhook Secret`. You'll need to supply these using the `WEBHOOK_IDS` and `WEBHOOK_SECRETS` configuration variable below to initialise the webhook for use. For more information on how to do this, see the [Setup Guide](https://github.com/jedda/step-posture-connector/wiki/Setup-Guide).

Both endpoints take an optional `mode` query string that may be needed depending what device you are targeting. At the moment this is required only by Jamf, as the API endpoints it uses to search and match iOS devices vs computers is different and `step-posture-connector` must be told which one is being requested. For Jamf, the webhook format should be as follows:

- `/webhook/device-attest?mode=mobiledevice` and `/webhook/scep-challenge?mode=mobiledevice` for iOS devices
- `/webhook/device-attest?mode=computer` and `/webhook/scep-challenge?mode=computer` for Mac computers

Note that Jamf lookup will default to `mode=mobiledevice` if a mode is not defined, so only `mode=computer` is actually required to specifically target Macs. If you are using Jamf and want to target both iOS and Mac, youll need to create two different provisioners in [`step-ca`](https://github.com/smallstep/certificates) - one for each platform with it's own appropriate webhook pointing at the correct mode.

The `file` and `mosyle` providers ignore the `mode` query and treat every device type as the same.

Each endpoint only accepts the request shape it's meant for: pointing an ACME webhook at
`/webhook/scep-challenge`, or a SCEP `SCEPCHALLENGE` webhook at `/webhook/device-attest`, is
rejected with a clear configuration error rather than silently doing the wrong thing.

### SCEP challenge webhooks

`/webhook/scep-challenge` accepts `SCEPCHALLENGE` webhooks from a SCEP provisioner - add one
pointing at this endpoint (see the `step ca provisioner webhook add ... --kind SCEPCHALLENGE`
command in `step-ca`'s documentation) to have `step-posture-connector` validate SCEP enrollments
the same way it validates ACME ones.

For a SCEP request, `step-posture-connector` checks two things before allowing certificate issuance:

1. the device serial number - read from the CSR subject's `serialNumber` attribute, or its common
   name if that attribute is absent - is registered (and compliant, where the provider supports
   compliance checks) with your chosen provider, exactly as for ACME;
2. the SCEP challenge presented by the client matches the challenge expected for that device.

The challenge check can work in one of two modes, configured per-provider (see the provider
configuration tables below):

- **Static** - a single challenge value, set directly as an environment variable
  (`<PROVIDER>_SCEP_CHALLENGE`). Any enrolled device presenting this value will pass the challenge
  check. This does not bind the challenge to a specific device - only the serial number lookup does
  that - so it offers weaker device-specific security than the dynamic mode below, but is the
  simplest option and mirrors `step-ca`'s built-in static SCEP `challenge`.
- **Dynamic** - the *name* of a field on the device's record is set as an environment variable
  (`<PROVIDER>_SCEP_CHALLENGE_KEY`), and `step-posture-connector` looks up that field's value, per
  device, from your provider. This lets you generate a unique challenge per device (eg. via a Mosyle
  custom field, or a Jamf extension attribute) and binds the challenge to the exact device it was
  issued for.

Only one of the two may be configured for a given provider - setting both will fail to bootstrap.
If neither is set, SCEP requests are denied (with a clear error) while ACME requests continue to be
served normally, so adding SCEP support is entirely optional for existing deployments.

## Compliance Group Membership

Where supported by the MDM provider, `step-posture-connector` can utilise Compliance Groups to ensure device posture baseline prior to certificate issuance.

This can be used to ensure that devices meet certain compliance criteria before being allowed to order an MDA ACME certificate. With Jamf, you can use a smart group to assess devices and computers against this criteria.

Where a group is defined, `step-posture-connector` will only allow a certificate to be issued if a device is a member of this group, and will deny other requests.


## Configuration

Configuration is performed via environment variables; able to be supplied in the shell, via a .env file or via Docker when using the supplied Docker image (recommended). `step-posture-connector` will validate configuration on start – including bootstrapping and checking your selected provider (although the error messages aren't super friendly or verbose - something to improve on later).

### Global Configuration

| Environment Variable | Required | Description |
| --- |  --- | ----------- |
| `PROVIDER` | required | Specifies which provider to use. Currently needs to be one of `file`, `jamf` or `mosyle`. |
| `TLS_CERT_PATH` | required | Specifies the file path of the PEM formatted certificate to use for the webhook server. |
| `TLS_KEY_PATH` | required | Specifies the file path of the private key to use for the webhook server. |
| `WEBHOOK_IDS` | required | Specifies a comma delimited list of `step-ca` webhook IDs. See "Webhooks" for details. |
| `WEBHOOK_SECRETS` | required | Specifies a comma delimited list of `step-ca` webhook secrets (matching the IDs supplied using 	`WEBHOOK_IDS`). See "Webhooks" for details. |
| `ENABLE_MTLS` | optional | Enables mutual TLS (mTLS) for requests to the webhook server. Needs to be `0` or `1`. |
| `TLS_CA_PATH` | required (with `ENABLE_MTLS `) | Specifies the file path of the PEM formatted CA to validate mTLS requests. |
| `PORT` | optional | Specifies which TCP port the HTTPS webserver will start on. Defaults to `9443`. |
| `LOGGING_LEVEL` | optional | Specifies the verbosity level of logging. needs to be one of `0` (allow/deny only), `1` (verbose), or `2` (debug). Defaults to `0`. |
| `TIMEOUT` | optional | A global timeout value used by providers for any HTTPS connections. Defaults to `10`. |

### Provider Configuration - File (`file`)

The following additional configuration variables apply when using the `file` provider.

| Environment Variable | Required | Description |
| --- |  --- | ----------- |
| `FILE_PATH` | required | Specifies the path to a file containing device data. |
| `FILE_TYPE` | required | Specifies the file type. Currently needs to be one of `csv` or `json`. |
| `FILE_SCEP_CHALLENGE` | optional | Specifies a static SCEP challenge. See "SCEP challenge webhooks" for details. Cannot be combined with `FILE_SCEP_CHALLENGE_KEY`. |
| `FILE_SCEP_CHALLENGE_KEY` | optional | Specifies the field name (a column header for `csv`, or a key under `data` for `json`) holding each device's dynamic SCEP challenge. See "SCEP challenge webhooks" for details. Cannot be combined with `FILE_SCEP_CHALLENGE`. |

### Provider Configuration - Jamf Pro (`jamf`)

The following additional configuration variables apply when using the `jamf` provider. You'll need to [create an appropriate API Role & Client in Jamf](https://learn.jamf.com/bundle/jamf-pro-documentation-current/page/API_Roles_and_Clients.html) to generate the ID and Secret. Role privileges required are `Read Mobile Devices` and `Read Computers` depending on which devices you are targeting.

| Environment Variable | Required | Description |
| --- |  --- | ----------- |
| `JAMF_BASE_URL` | required | Specifies the base URL for your Jamf instance (eg. https://example.jamfcloud.com) |
| `JAMF_CLIENT_ID` | required | Specifies the Jamf API OAuth client ID used to request a bearer token. |
| `JAMF_CLIENT_SECRET` | required | Specifies the Jamf API OAuth client secret used to request a bearer token. |
| `JAMF_DEVICE_GROUP` | optional | When included, specifies a Jamf Mobile Device group to check membership against for iOS devices. |
| `JAMF_COMPUTER_GROUP` | optional | When included, specifies a Jamf Computer group to check membership against for Mac devices. |
| `JAMF_DEVICE_ENRICH` | optional | Specifies if user enrichment data should be returned to `step-ca` for Mobile Devices. Needs to be `0` or `1`. Defaults to `0`. |
| `JAMF_COMPUTER_ENRICH` | optional | Specifies if user enrichment data should be returned to `step-ca` for Computers. Needs to be `0` or `1`. Defaults to `0`. |
| `JAMF_SCEP_CHALLENGE` | optional | Specifies a static SCEP challenge. See "SCEP challenge webhooks" for details. Cannot be combined with `JAMF_SCEP_CHALLENGE_KEY`. |
| `JAMF_SCEP_CHALLENGE_KEY` | optional | Specifies the name of a Jamf extension attribute holding each device's dynamic SCEP challenge. See "SCEP challenge webhooks" for details. Cannot be combined with `JAMF_SCEP_CHALLENGE`. |

### Provider Configuration - Mosyle Business/Manager (`mosyle`)

The following additional configuration variables apply when using the `mosyle` provider. You'll need to generate an API access token from your Mosyle Business or Manager console.

| Environment Variable | Required | Description |
| --- |  --- | ----------- |
| `MOSYLE_BASE_URL` | required | Specifies the base URL for the Mosyle API including the version prefix (eg. `https://businessapi.mosyle.com/v1`). |
| `MOSYLE_ACCESS_TOKEN` | required | Specifies the Mosyle API access token used to authenticate the login request. |
| `MOSYLE_EMAIL` | required | Specifies the email address of the Mosyle account used to obtain a bearer token. |
| `MOSYLE_PASSWORD` | required | Specifies the password of the Mosyle account used to obtain a bearer token. |
| `MOSYLE_TAGS` | optional | When included, specifies a comma-delimited list of Mosyle tags. Devices must carry at least one of these tags to be allowed. |
| `MOSYLE_ENRICH` | optional | Specifies if enrichment data should be returned to `step-ca`. Needs to be `0` or `1`. Defaults to `0`. |
| `MOSYLE_SCEP_CHALLENGE` | optional | Specifies a static SCEP challenge. See "SCEP challenge webhooks" for details. Cannot be combined with `MOSYLE_SCEP_CHALLENGE_KEY`. |
| `MOSYLE_SCEP_CHALLENGE_KEY` | optional | Specifies the Custom Device Attribute holding each device's dynamic SCEP challenge, matched against its unique identifier (eg. `%custom_cc_scepChallenge%` - surrounding `%` characters are stripped automatically, so a Mosyle profile variable can be pasted as-is) or, failing that, its display name. A deleted attribute is ignored. See "SCEP challenge webhooks" for details. Cannot be combined with `MOSYLE_SCEP_CHALLENGE`. |

When `MOSYLE_ENRICH` is enabled, the following data is returned to `step-ca` and can be used in certificate templates:

```json
{
  "device": {
    "udid": "...",
    "serial_number": "...",
    "name": "...",
    "model": "...",
    "os": "macOS",
    "os_version": "14.4.1",
    "is_supervised": true,
    "enrollment_type": "DEP"
  },
  "user": {
    "userid": "..."
  },
  "tags": ["corp", "production"]
}
```

Unlike Jamf, the Mosyle API endpoint is unified across all device types, so a single provisioner and webhook can handle multiple platforms. The `mode` query parameter maps to the Mosyle `os` value as follows:

| `mode` query value | Mosyle `os` |
| --- | --- |
| (empty) or `mobiledevice` | `ios` |
| `computer` | `mac` |
| `tvos` | `tvos` |
| `visionos` | `visionos` |

If you need to support multiple platforms, you can create separate provisioners in [`step-ca`](https://github.com/smallstep/certificates) each pointing at the same webhook URL with a different `mode` parameter, or use a single provisioner without a `mode` to default to iOS/iPadOS.

## Usage Philosophy & Considerations

When using this tool, it's important to consider the security concepts of identification, authentication and authorisation and how they apply to any resources being accessed with issued certificates. 

I've [written about this in further depth as part of a technical explortation into Managed Attestation for Apple devices](https://jedda.me/managed-device-attestation-a-technical-exploration/) which is worth a read if you want to better understand the concepts.

How you use the device attestation certificates facilitated by [`step-ca`](https://github.com/smallstep/certificates) and Step Posture Connector is entirely up to you, however 802.1x & VPN (& mTLS on iOS) are the obvious usage candidates. For the most part, certificates enriched with a user identity can identify a user and even stand in as an authentication method, but they likely don't authorise a user against specific services nor attest to the current status of that user. Where possible, take care to validate the certificate and any user identity SANs during consumption by services to ensure user posture alongside that of the device.


### iOS vs macOS Use Cases

Due to differences in how keychains are implemented on iOS vs macOS, there are currently some significant differences in how hardware bound certficates can be utilised on each platform.

On macOS, the issued cert gets stored in the data protection keychain which means it's not available in Keychain Access or even using the `security ` command. MDM can get details of the cert by using the `CertificateList` command, but browsers won't see it (so no mTLS) and on-device posture clients (such as Cloudflare WARP, Zscaler, ect) won't see it  so can't be used to evidence device posture.	This really limits the usage of the certificate to the config profile it ships in, and likely to 801.1x and VPN payloads for the time being. Hopefully we see this change in future versions of macOS to allow for powerful mTLS & device posture flows into ZTNA, ect.

On iOS this is a slightly better story, as the issued cert is stored in the Apple keychain access group which makes it available to Safari (and other Apple apps) for use as an mTLS client certificate as well as the profile payloads (801.1x and VPN) available on macOS.

### Attested Device Permanent Identifiers

Under my testing in the current implementations of Managed Device Attestation on macOS devices (Apple Silicon & Intel with T2, Sonoma 14.1), the following are returned as permanent identifier options by Apple's attestation servers:

- Device Serial Number
- Device Provisioning UDID

Note that this "Device Provisioning UDID" is not the "Hardware UUID" (or UDID as reported to some MDMs), but instead the "Device Provisioning UDID" (viewable in macOS System Information/Report) which is not by default captured by MDM.

When using MDM providers for matching, this means the Device Provisioning UDID isn't really a suitable candidate as a matching identifier, so for Jamf we currently support Device Serial Number only. I can't find a lot of documentation on this, so if i'm wrong here or there is a better way I'd love to be pointed in a better direction.

## Questions, Issues & Discussions

Feel free to [start a discussion](https://github.com/jedda/step-posture-connector/discussions) or [create an issue](https://github.com/jedda/step-posture-connector/issues). You are also welcome to [DM me on the Mac Admins Slack](https://macadmins.slack.com/team/U1QABUHAR).
