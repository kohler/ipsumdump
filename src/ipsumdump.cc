#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
#include <click/config.h>
#include <click/clp.h>
#include <click/error.hh>
#include <click/confparse.hh>
#include <stdio.h>
#include <stdlib.h>

#define HELP_OPT	300
#define VERSION_OPT	301

static Clp_Option options[] = {

  { "help", 'h', HELP_OPT, 0, 0 },
  { "version", 'v', VERSION_OPT, 0, 0 },
  
};

static const char *program_name;

void
short_usage(const char *specific = 0)
{
  if (specific)
    fprintf(stderr, "Command line error: %s\n", specific);

  fprintf(stderr, "Usage: %s [OPTION]...\n\
Try `%s --help' for more information.\n",
	  program_name, program_name);
}

void
usage(const char *specific = 0)
{
  if (specific)
    fprintf(stderr, "Command line error: %s\n", specific);

  fprintf(stderr, "Usage: %s [OPTION]...\n\
Try `%s --help' for more information.\n",
	  program_name, program_name);
}

int
main(int argc, char *argv[])
{
    Clp_Parser *clp = Clp_NewParser
	(argc, argv, sizeof(options) / sizeof(options[0]), options);
    program_name = Clp_ProgramName(clp);
    
    String::static_initialize();
    cp_va_static_initialize();
    ErrorHandler *errh = new FileErrorHandler(stderr, "");
    ErrorHandler::static_initialize(errh);
    ErrorHandler *mq_errh = new PrefixErrorHandler(errh, String(program_name) + ": ");

    while (1) {
	int opt = Clp_Next(clp);
	switch (opt) {
	    
	  case HELP_OPT:
	    usage();
	    exit(0);
	    break;

	  case VERSION_OPT:
	    fprintf(stderr, "Cpyright MY BIGG FAT HAIRY ASSSS (c)\n");
	    exit(0);
	    break;

	  case Clp_NotOption:
	  case Clp_BadOption:
	    short_usage();
	    exit(1);
	    break;

	  case Clp_Done:
	    goto done;

	  default:
	    assert(0);
	    
	}
    }
  
  done:
    exit(0);
}
