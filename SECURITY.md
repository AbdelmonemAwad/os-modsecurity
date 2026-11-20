# Security

## Reporting a vulnerability

**Not in a public issue, please.** Report it privately through GitHub -
[**Report a vulnerability**](https://github.com/AbdelmonemAwad/os-modsecurity/security/advisories/new),
on the Security tab - where only you and the owner see it, and the fix can be prepared before anything is
public. Without a GitHub account, write to **security@npuforge.org**. Either way, include:

- what is affected - its page and what it configures;
- the appliance, the version you installed, and the OPNsense version;
- how to reproduce it, and what you saw.

This is one person's project, worked on in the evenings: expect an answer within days, not hours.
A fix is made in a pull request and the reporter credited in it, unless they ask not to be.

## What is supported

The newest version on `main`, and the newest release where there are releases. Fixes go there,
with no backports.

## Worth knowing before you report

- A request reaching a site's backend in Blocking that the Core Rule Set at its paranoia level refuses, Apache listening where the page did not put it or on a port the web GUI holds, a certificate's key readable by anyone but root, a Core Rule Set installed that is not the one signed, or the page showing other than what is applied, is a problem - report it here.
- **Never send a configuration backup.** It holds keys and passwords.
