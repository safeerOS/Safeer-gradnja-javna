# Safeer gradnja

Build workflow for Safeer's own WebKitGTK package (`safeer-webkit`). The workflow is started by hand only.
Build inputs that are not yet public are kept in `zaupno/prekrivalo.tar.gpg`, encrypted with the public key in
`zaupno/kljuc.pub.asc`; the runner decrypts them with a repository secret, and final build outputs are encrypted
for a separate key (`zaupno/kljuc-izhodi.pub.asc`) whose private part is not on the runner, so the runner cannot read
them back (`tools/zaupno.py`).

Safeer team, https://safeer.si
