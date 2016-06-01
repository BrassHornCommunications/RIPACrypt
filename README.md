# RIPACrypt
This is the client side application for [RIPACrypt](https://ripacrypt.download) which remotely stores secrets which are destroyed if a deadline is reached without a checkin (a form a deadman switch).

This is another thought experiment in defeating the Regulation of Investigatory Powers Act 2000 Section 49 (compelled decryption) legislation using technology.

## Process
We do not provide prebuilt binaries so that you can ensure that the code you are running is doing what we say it is.

1. Prepare your [GoLang work directory](https://golang.org/doc/code.html#Workspaces)
2. Issue `go get github.com/BrassHornCommunications/RIPACrypt`
3. Issue `cd src/github.com/BrassHornCommunications/RIPACrypt`
4. Issue `go build -o rcrypt && sudo cp rcrypt /usr/local/bin/`
5. Follow instructions below

## Using RIPACrypt

The simplest way to use RIPACrypt is to register a new account _(allowing the client to generate a new GPG key pair)_ and then piping in the content you want to encrypt and store _(accepting the 3 day expiry default)_

Please note that you do not have to use this client, the API is very easy to use _(to the point you can just use `bash`, `curl`, `gpg` and `base64`. See [ExampleCurlCalls](https://github.com/BrassHornCommunications/RIPACryptd/blob/master/ExampleCurlCalls.md) for more details.)_

### Registering
```rcrypt register```

This will create `~/ripacrypt/rc.conf` which will contain your user ID, your unique bitcoin address and your GPG key pair.

### Encrypt and Store Some Data _(with a 3 day expiry)_
```echo "MySuperStrongPassphrase" | rcrypt new -description="Something that obscurely links this crypt with the protected data"```

RIPACrypt will encrypt the data you passed with the public keypair generated earlier _(Note: This encryption can be considered 'end-to-end' as we never have access to your private key)_ and then submits it to the server.

You will need to checkin at least every 3 days _(72 hours)_ or your crypt will be destroyed _(but preferably every 24 hours)_.

### Checkin with your crypt
```rcrypt checkin -crypt=CRYPTHASH```

Checking in with a crypt will 'reset' the self destruction countdown. Failing to checkin within the configured limit _(default of 3x 24 hours)_ will result in a crypt being destroyed.

### My Computer has been seized and I've been served a RIPA s.49 Notice
Assuming the RIPA s.49 notice has been issued _after_ the crypts self destruction deadline simply provide your Crypt ID and explain RIPA Crypt _(See Disclaimers below!!!)_

## Advanced Usage
### `[register new checkin getchallenge newbtc]` -usetor
Attempts to connect to the RIPACrypt service via the SOCKS5 proxy exposed by Tor

### `[register new checkin getchallenge newbtc]` -debug
Will print the full JSON reply from the API for any query

### `new` -description="x"
Provides a description of the crypt that can help prove that this destroyed crypt held the passphrase for your disks. Examples could be the serial number of the storage media in question.

### `new` -checkincount=x -misscount=y
Choose different checkin _(in seconds)_ and miss counts. E.g. you could specify 30 minutes _(1800 seconds)_ with a miss count of 5, providing a total of 2 and half hours before self destruction.

The reason for having two variables is that in future versions we might enable notifications for each missed duration.

## Development
- [x] Register
- [x] Create a new crypt
- [x] Checkin with crypt
- [x] Get a challenge
- [x] Get a new Bitcoin address
- [ ] Delete a crypt
- [ ] Specify a notification method if a checkin period is missed

## Pull Requests And Development

Whilst this is a working SaaS product the main purpose of the project is to get people thinking about the perils of laws that can compel decryption.

With that said we would appreciate any pull requests / issues / suggestions / help.

## Disclaimers
**We are not a lawyers, solictiors or in any way well versed in the law. This software may result in you being found guilty of Failure to comply with a notice under the Regulation of Investigatory Powers Act 2000 and sentenced to up to 5 years in prison (or worse)**

> THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. 
