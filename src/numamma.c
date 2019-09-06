#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <argp.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>

#include "numamma.h"

#define SAMPLING_RATE -1
#define NO_MATCH_SAMPLE -2
#define ONLINE_ANALYSIS -3
#define NO_REFRESH -4
#define BUFFER_SIZE -5
#define GET_AT_ANALYSIS -6

// todo : make better string length checks, for now this is not safe from buffer overflows
#define STRING_LENGTH 4096

// CMake .c.in here
const char prefix[] = INSTALL_PREFIX;
const char numap_libdir[] = "";

const char *program_version = "numamma";
const char *program_bug_address = "";
static char doc[] = "Numamma description";
static char args_doc[] = "target [TARGET OPTIONS]";

const char * argp_program_version="NumaMMA dev";

// long name, key, arg, option flags, doc, group
// if key is negative or non printable, no short option
static struct argp_option options[] = {
	{0, 0, 0, 0, "Outputs options :"},
	{"verbose", 'v', 0, 0, "Produce verbose output" },
	{"dump", 'o', 0, 0, "Enable memory dump"},
	{0, 0, 0, 0, "Another group :"},
	{"sampling-rate", SAMPLING_RATE, "RATE", 0, "set sampling rate to RATE"},
	{"sr", SAMPLING_RATE, 0, OPTION_ALIAS},
	{"no-match-samples", NO_MATCH_SAMPLE, 0, 0, "do not match samples"},
	{"online-analysis", ONLINE_ANALYSIS, 0, 0, "enable online analysis"},
	{"alarm", 'a', "INTERVAL", 0, "set alarm interval (must be long)"},
	{"no-refresh", NO_REFRESH, 0, 0, "disable perf event refresh"},
	{"buffer-size", BUFFER_SIZE, "SIZE", 0, "set buffer size"},
	{"get-at-analysis", GET_AT_ANALYSIS, "NB", 0, "if NB>0, call ma get functions before analysis, uppon online analysis, will be done before each NB first analysis"},
	{0}
};

struct arguments {
	bool verbose;
	bool dump;
	char* sampling_rate;
	bool match_samples;
	bool online_analysis;
	char* alarm;;
	bool refresh;
	char* buffer_size;
	char* get_at_analysis;
};

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	/* Get the input argument from argp_parse, which we
	 * know is a pointer to our arguments structure. */
	struct arguments *arguments = state->input;

	switch(key)
	{
		case 'v':
			arguments->verbose = true;
			break;
		case 'o':
			arguments->dump = true;
			break;
		case SAMPLING_RATE:
			arguments->sampling_rate = arg;
			break;
		case NO_MATCH_SAMPLE:
			arguments->match_samples = false;
			break;
		case ONLINE_ANALYSIS:
			arguments->online_analysis = true;
			break;
		case 'a':
			arguments->alarm = arg;
			break;
		case NO_REFRESH:
			arguments->refresh = false;
			break;
		case BUFFER_SIZE:
			arguments->buffer_size = arg;
			break;
		case GET_AT_ANALYSIS:
			arguments->get_at_analysis = arg;
			break;
		case ARGP_KEY_NO_ARGS:
			argp_usage(state);
			break;
		case ARGP_KEY_ARG:
		case ARGP_KEY_END:
			// nothing to do
			break;
		default:
			return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static struct argp argp = { options, parse_opt, args_doc, doc };

int main(int argc, char **argv)
{
	struct arguments arguments;

	// Default values
	arguments.verbose = false;
	arguments.dump = false;
	arguments.sampling_rate = NULL;
	arguments.match_samples = true;
	arguments.online_analysis = false;
	arguments.alarm = NULL;
	arguments.refresh = true;
	arguments.buffer_size = NULL;
	arguments.get_at_analysis = NULL;

	// first divide argv between numamma options and target file and options
	// optionnal todo : better target detection : it should be possible to specify both --option=value and --option value, but for now the latter is not interpreted as such
	int target_i = 1;
	while (target_i < argc && argv[target_i][0] == '-') target_i++;
	if (target_i == argc)
	{
		// there are no arguments, either the user entered --help or something like that, either we want to print usage anyway
		return argp_parse(&argp, argc, argv, 0, 0, &arguments);
	}
	
	char **target_argv = NULL;
	if (target_i < argc)
		target_argv = &(argv[target_i]);
	// we only want to parse what comes before target included
	argp_parse(&argp, target_i+1, argv, 0, 0, &arguments);

	char ld_preload[STRING_LENGTH] = "";
	char *str;
	if ((str = getenv("LD_PRELOAD")) != NULL) {
		strncpy(ld_preload, str, STRING_LENGTH);
		strcat(ld_preload, ":");
	}
	strcat(ld_preload, prefix);
	strcat(ld_preload, "/lib/libnumamma.so");
	
	char ld_library_path[STRING_LENGTH] = "";
	if ((str = getenv("LD_LIBRARY_PATH")) != NULL) {
	  strncpy(ld_library_path, str, STRING_LENGTH);
	  strcat(ld_library_path, ":");
	}
	strcat(ld_library_path, numap_libdir);

	setenv("LD_PRELOAD", ld_preload, 1);
	setenv("LD_LIBRARY_PATH", ld_library_path, 1);
	if (arguments.verbose)
		setenv("NUMAMMA_VERBOSE","1", 1);
	if (arguments.dump)
		setenv("NUMAMMA_DUMP","1", 1);
	if (arguments.sampling_rate != NULL)
		setenv("SAMPLING_RATE", arguments.sampling_rate, 1);
	if (!arguments.match_samples)
		setenv("DONT_MATCH_SAMPLES", "1", 1);
	if (arguments.online_analysis)
		setenv("ONLINE_ANALYSIS", "1", 1);
	if (arguments.alarm != NULL)
		setenv("NUMAMMA_ALARM", arguments.alarm, 1);
	if (!arguments.refresh)
		setenv("NUMAMMA_NO_REFRESH", "1", 1);
	if (arguments.buffer_size != NULL)
		setenv("NUMAMMA_BUFFER_SIZE", arguments.buffer_size, 1);
	if (arguments.get_at_analysis != NULL)
		setenv("NUMAMMA_GET_AT_ANALYSIS", arguments.get_at_analysis, 1);
	extern char** environ;
	int ret;
	if (target_argv != NULL) {
		ret  = execve(argv[target_i], target_argv, environ);
	} else {
		char *no_argv[] = {NULL};
		ret = execve(argv[target_i], no_argv, environ);
	}
	// execve failed
	fprintf(stderr, "Could not execve : %d - %s\n", errno, strerror(errno));
	return EXIT_FAILURE;
}
