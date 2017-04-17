# eyefidocker

[Eye-Fi](http://www.eyefi.com/) cards let your fancy-but-not-fancy-enough-to-have-wifi camera upload your pictures to the web without having to fiddle with a bunch of software. The idea was that you paid for this little superpowered SD card and then it would make your life permanently more convenient. What a great idea!

Except, uh oh, there's a problem. Eye-Fi realized that this deal only involves them getting paid _once_, instead of _forever_. You can see why this would upset someone who's trying to sell a product. It seems unfair! So now you buy this expensive SD card and that gives you the right to pay forever for Eye-Fi's lousy web photo service. Hooray?

Well, we can do better. I'm a longtime Flickr user. That's where I want to put my photos. With a spare computer like a Raspberry Pi, we can take over the Eye-Fi upload procedure and send the photos wherever we damn well please.

This project is a fork of [eyefiserver2](https://github.com/dgrant/eyefiserver2). It adds two capabilities:

- Dockerization
- Flickr uploads

It also tears out a bunch of unnecessary code and modernizes a thing or two.

You will need to be able to use your system's command-line to pull this off. Sorry.

## Installing Docker

You should install [Docker](https://www.docker.com/), the amazing virtualization-but-not-really technology that provides a pleasantly reliable computing environment for projects like this one. Their website will tell you how. The following instructions assume a Linux or OS X system, but it's probably possible to get this all working on Windows somehow (though tbh someone should just bake a Windows exe instead of going the Docker route).

## Configuring eyefiserver.conf

You should adjust the values in `eyefiserver.conf` to reflect your card MAC address and upload key. These can be obtained by installing Eye-Fi's proprietary `Keenai` software and completing initial card configuration. On OS X, the relevant values can then be found with the following two commands.

The MAC address:

```sh
echo "select o_mac_address from o_devices;" | sqlite3 "$HOME/Library/Application Support/Keenai/offline.db" | tr -d '-'
```

The upload key:

```sh
echo "select o_upload_key from o_devices;" | sqlite3 "$HOME/Library/Application Support/Keenai/offline.db"
```

## Configuring Flickr credentials

Setting up Flickr consists of building the Docker image, using it to configure Flickr credentials and then rebuilding the image. With that complete you can run the final image. Note that after configuration is complete your Flickr API credentials will be baked into the image and the files in this directory! These credentials will be scoped to only allow read & write access, not deletion capabilities. You should still be aware of the security risk this poses and protect access to these resources. Do not share a configured system with other users -- point them to this project's Github repository.

To configure Flickr credentials:

1. Log in to Flickr, then retrieve an API key and secret from [https://www.flickr.com/services/apps/create/noncommercial/](https://www.flickr.com/services/apps/create/noncommercial/). Add these values to `eyefiserver.conf` as `flickr_key` and `flickr_secret`. While you're there, ensure `flickr_enable` is set to 1.
2. Build the Docker image: `docker build -t eyefiserver:main .`
3. Create a Docker container, mounting the current directory: `docker run -v $(pwd):/tmp/src --rm -t -i eyefiserver:main`. The script will detect that Flickr functionality is enabled but not fully configured. It will output a URL that you should paste into your browser. You will be prompted to grant permissions. Once you do, your browser will display some XML that includes an `oauth_verifier` value. Copy this value and paste it into the docker console at the prompt.
4. Rebuild the Docker image. This should be faster the second time! `docker build -t eyefiserver:main .`

## Run the server

Start the server with the appropriate port exposed: `docker run --rm -t -i -p 59278:59278 eyefiserver:main`. You might want to use a mechanism like Upstart to do this automatically on your chosen host machine. But you can also just use the `run` command when needed.

Your Eye-Fi card, when properly configured to join the same network as your server, will scan its local subnet for a server listening port 59278 and upload images to it. Be sure you're not running Eye-Fi's own software anywhere, or the card might find that server first.

Nikon owners: be aware that recent camera firmwares contain an Eye-Fi specific setting that disables uploads to conserve power. You will need to enable uploads through your camera's on-screen menu system for any of this to work.
