# Welcome to the Ultranet

The Ultranet is a new type of marketplace that's fully decentralized, private, and
censorship-resistant. It also includes a fully decentralized cryptocurrency exchange
platform, a fully decentralized messaging platform, and a native hyper-deflationary
cryptocurrency called Ultra.

## Context
The white paper, which can be found on [ultranet.one](http://ultranet.one), contains the best primer on
the Ultranet's core technical concepts (particularly the section entitled "The Ultranet's Design"). 

### Key Features
* Offers a higher level of privacy and censorship-resistance than any
  marketplace platform that exists today.
    - Fully decentralized and pseudo-anonymous like Bitcoin and
    everything is generally end-to-end encrypted.
    - As long as a single node somewhere in the world is running, all data,
      including all listings and reputation data, is preserved.
    - This is made possible through a new concept we introduce in the paper
      called a “block pool.”
* Comes packaged with a rich graphical user interface that provides a
  user experience that is on-par with existing non-decentralized,
  non-private alternatives.
* Includes a built-in decentralized cryptocurrency exchange
  platform, a built-in decentralized messaging platform, and a
  hyper-deflationary cryptocurrency called Ultra.
    - The decentralized exchange embedded in its software allows any user
      to seamlessly exchange Bitcoin for Ultra without any involvement from
      any third parties, a feature made possible by a new concept we 
      introduce in the paper called “interchange” (Monero can also be used).
        + The complexity of the decentralized exchange mechanism is 
          completely abstracted away from the user, making the experience 
          feel identical to depositing and exchanging coins on a 
          centralized exchange.
    - The messaging platform is end-to-end encrypted and
      fully-decentralized.
    - Ultra, the cryptocurrency native to the Ultranet platform, is
      hyper-deflationary in the long run (much more so than Bitcoin in
      fact), and can power a network effect to bootstrap usage of the 
      platform.
        + We refer to Ultra as “digital oil” because, unlike Bitcoin or
          Ethereum, it is constantly “burning” away over time through
          commissions as users make purchases, thus making it more and more
          scarce.
* These features are implemented on a new type of blockchain written
  entirely from-scratch in Go.
* In the paper we also present a proposal that uses the decentralized
  exchange concept to scale blockchains to thousands of transactions per
  second without compromising on decentralization or
  censorship-resistance.
* In the long run, the aim is to make the Ultranet into a “Decentralized
  Platform Monopoly,” introducing an open-source challenger to take on
  the “Platform Oligarchy” that rules over us today (i.e. the tech giants).

### Preview
Below is a screenshot of what the home screen looks like when one runs
the software.

![](https://raw.githubusercontent.com/sarahc0nn0r/ultranet/master/screenshot.png "Welcome to the Ultranet")

## Development

### Code Structure
The Ultranet has two components: a frontend and a backend. Nearly all of the core
functionality is defined in the backend, which exposes an API that the frontend
uses to wrap the functionality in a nice UI. The backend is written in Go while the
frontend is an Angular app that runs in a browser and typically connects to a
backend running on localhost.

### Dependencies
The Ultranet was developed on a Linux environment and compiled for other platforms
using Go's built-in cross-platform compilation functionality. As such, development
will likely proceed most smoothly if you compile on a Linux machine, but this is not
strictly necessary.

Below is a list of things that are required in order to build the Ultranet:

* Go 1.12.6 or higher
* Nodejs
* AngularCLI and typescript 
    * sudo npm install -g @angular/cli typescript tslint
* Virtualbox for testing all three platforms (Windows, Linux, Mac)

### Building
If you run into problems building the software, please create an issue with as much
detail as possible so someone can help you.

Run the following commands from the top-level directory to download dependencies:

  * (cd frontend && npm install)
  * (cd backend && go get ./...)

To build everything after dependencies have been installed simply run the 
following command from the top of the repository:

  * ./build.sh

This will build six binaries in total for the outer product of (32-bit, 64-bit) x (Windows, Mac, Linux).
The backend and frontend have similar files nested in their respective subdirectories
so you can build them individually.

### Running Tests
All tests can be run with the following command:

  * (cd backend && go test lib/*.go -v)

You can get even more verbosity by setting the vlog level higher with the following command:

  * (cd backend &&  go test lib/*.go -v --args --v=2)

### Running Nodes
You can run nodes that connect to the mainnet or nodes that create a local "testnet."
To run a test node that connects to the mainnet, use the following commands (it should
open up a browser pointing to the node that's running):

  * cd bachend/scripts/test_nodes
  * ./n0 # or ./n1 or ./n2

To run nodes that spin up their own testnet, simply run n0_test rather than n0. The
test nodes are configured to connect to each other directly (n0 -> n1 -> n2) so you
can run all three as a sort of integration test.

You can also manually run a node by simply executing the binary that is
compiled by running the build script. Below is an example (and the test
scripts mentioned above show other examples that involve using vmodule
fine-grained logging among other things):

  * ./backend --alsologtostderr

### Logging
The node code uses glog for logging, which means you can have fine-grained
control over what is printed. Generally, --v=0 is what you get by default,
--v=1 is a more verbose level, and --v=2 is the most verbose (we don't go
deeper than level 2).

To control the log level for a particular file you can use vmodule, for
example, the below will run a node normally, except that all log statements
in server.go will log at level 2:

  * ./backend --alsologtostderr --vmodule=*server*=2

By default, logs are written to $TMPDIR/program_params/.../*.log. Every time
you run the program, a new directory is created with the logs for that specific
run. A symlink is always created pointing to the latest run so you can simply
look at that for whatever run you're currently on. The --alsologtostderr
flag ensures that log output is logged to stderr and not just to the folder.

You can grep the logs for particular IP addresses to see the activity with
a particular node, among other things.

## Contact
If you run into any trouble while trying to do something, please create an
issue with as much information about your problem as possible. Over time, we
can compile the common issues into an FAQ.
