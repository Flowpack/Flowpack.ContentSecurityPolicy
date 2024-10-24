# Flowpack.ContentSecurityPolicy

<!-- TOC -->

* [Flowpack.ContentSecurityPolicy](#flowpackcontentsecuritypolicy)
    * [Introduction](#introduction)
    * [Usage](#usage)
    * [Custom directives and values](#custom-directives-and-values)
        * [Show CSP configuration](#show-csp-configuration)
    * [Disable or report only](#disable-or-report-only)
    * [Nonce](#nonce)
    * [Backend](#backend)
    * [Thank you](#thank-you)

<!-- TOC -->

## Introduction

Flow/Neos package to set your site's content security policy header easily with yaml.

## Usage

Import the package using composer:

```bash
composer require flowpack/content-security-policy
```

The package is automatically active once imported.
By default, the response header `Content-Security-Policy` will now be included.

It will use the default configuration which looks like this:

```yaml
Flowpack:
  ContentSecurityPolicy:
    enabled: true
    report-only: false
    content-security-policy:
      default:
        base-uri:
          - 'self'
        connect-src:
          - 'self'
        default-src:
          - 'self'
        form-action:
          - 'self'
        img-src:
          - 'self'
        media-src:
          - 'self'
        frame-src:
          - 'self'
        object-src:
          - 'self'
        script-src:
          - 'self'
        style-src:
          - 'self'
        style-src-attr:
          - 'self'
        style-src-elem:
          - 'self'
        font-src:
          - 'self'
      custom: [ ]
```

Now only resources from the same origin are allowed for the most common directives.
It is enabled by default and the report-only mode is disabled.

## Custom directives and values

If you want to override the default config don't forget to add this package as a dependency in the composer.json file
of your package. Otherwise, it might not work because of the loading order of the packages.

The default configuration will probably not suit your needs so you can add your own configuration by adding the array
custom like this in your own yaml configuration files:

```yaml
Flowpack:
  ContentSecurityPolicy:
    content-security-policy:
      custom:
        frame-src:
          - 'https://www.youtube.com'
          - 'https://staticxx.facebook.com'
```

If you fully want to override the entire default config then just override the default key in yaml.

### Show CSP configuration

To show the parsed configuration, the built-in command `./flow cspconfig:show` can be used.
It shows all directives used by the frontend and the backend.

## Disable or report only

To disable the header simply set `enabled` to false.
If you want to add it as a report only header set `report-only` to true.
That way you have the option to see the possible errors without breaking functionality.

## Nonce

You might want to use a nonce to allow inline scripts and styles to be still secure.
To do this simply add `{nonce}` as an option in a directive. Like this:

```yaml
Flowpack:
  ContentSecurityPolicy:
    content-security-policy:
      custom:
        script-src:
          - '{nonce}'
```

Now the header will include a `nonce-automatedgeneratedrandomstring` in the script-src directive.
So inline scripts without the corresponding nonce will be blocked.

The nonce will be automatically added to all your script/style tags.

## Backend

Due to the current nature of the Neos backend being rendered a bit different then the frontend a separate policy is
added for the backend.
I currently have found no suitable way the add the nonce in the inline scripts in the Neos UI package.
So the CSP for the backend looks like this:

```yaml
Flowpack:
  ContentSecurityPolicy:
    content-security-policy:
      backend:
        base-uri:
          - 'self'
        connect-src:
          - 'self'
        default-src:
          - 'self'
        form-action:
          - 'self'
        img-src:
          - 'self'
          - 'data:'
        media-src:
          - 'self'
        frame-src:
          - 'self'
        object-src:
          - 'self'
        script-src:
          - 'self'
          - 'unsafe-inline'
          - 'unsafe-eval'
        style-src:
          - 'self'
          - 'unsafe-inline'
        style-src-attr:
          - 'self'
          - 'unsafe-inline'
        style-src-elem:
          - 'self'
          - 'unsafe-inline'
        font-src:
          - 'self'
          - 'data:'
      custom-backend: [ ]
```

Unsafe inline scripts and styles are allowed in the backend because otherwise the backend won't work.

Again you can add your own policies in the custom-backend array the same way as the custom array for the frontend.

## Thank you

This package originates from https://github.com/LarsNieuwenhuizen/Nieuwenhuizen.ContentSecurityPolicy.

Thank you Lars Nieuwenhuizen for your work.
