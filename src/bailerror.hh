#ifndef BAILERROR_HH
#define BAILERROR_HH
#include <click/error.hh>


class BailErrorHandler : public ErrorVeneer { public:

  BailErrorHandler(ErrorHandler *errh)	: ErrorVeneer(errh) { }

  void handle_text(Seriousness, const String &);
 
};

#endif
