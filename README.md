# Safeer gradnja

Build workflow for Safeer's own WebKitGTK package (`safeer-webkit`). The workflow is started by hand only.
Build inputs that are not yet public are kept in `zaupno/prekrivalo.tar.gpg`, encrypted with the public key in
`zaupno/kljuc.pub.asc`; the runner decrypts them with a repository secret, and every build output is encrypted
again with the public key only, so the runner itself cannot read it back (`tools/zaupno.py`).

Safeer team, https://safeer.si
