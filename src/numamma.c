#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <argp.h>
#include <unistd.h>
#include <errno.h>

#include "numamma.h"

#define ONLINE_ANALYSIS -1

// todo : make better string length checks, for now this is not safe from buffer overflows
#define STRING_LENGTH 4096

// CMake .c.in here
const char prefix[] = INSTALL_PREFIX;
const char numap_libdir[] = "";

const char *program_version = "numamma";
const char *program_bug_address = "";
static char doc[] = "Numamma description";
static char args_doc[] = "target_application [TARGET OPTIONS]";
const char * argp_program_version="NumaMMA dev";

// long name, key, arg, option flags, doc, group
// if key is negative or non printable, no short option
static struct argp_option options[] = {
	{0, 0, 0, 0, "Output options:"},
	{"verbose", 'v', 0, 0, "Produce verbose output" },

	{0, 0, 0, 0, "Collect options:"},
	{"sampling-rate", 'r', "RATE", 0, "Set the sampling rate (default: 10000)"},
	{"alarm", 'a', "INTERVAL", 0, "Collect samples every INTERVAL ms (default: disabled)"},
	{"flush", 'f', "yes|no", OPTION_ARG_OPTIONAL, "Flush the sample buffer when full (default: yes)"},
	{"buffer-size", 's', "SIZE", 0, "Set the sample buffer size (default: 128 KB per thread)"},
	{"canary-check", 'c', 0, 0, "Check for memory corruption (default: disabled)"},

	{0, 0, 0, 0, "Report options:"},
	{"outputdir", 'o', "dir", 0, "Specify the directory where files are written (default: /tmp/numamma_$USER"},
	{"match-samples", 'm', "yes|no", OPTION_ARG_OPTIONAL, "Match samples with the corresponding memory object (default: yes)"},
	{"online-analysis", ONLINE_ANALYSIS, 0, 0, "Analyze samples at runtime (default: disabled)"},
	{"dump-all", 'D', 0, 0, "dump all memory objects (default: disabled)"},
	{"dump", 'd', 0, 0, "Dump the collected memory access (default: disabled)"},
	{"dump-unmatched", 'u', 0, 0, "Dump the samples that did not match a memory object (default: disabled)"},
	{"no-dump-single-items", 'n', 0, 0, "If dump is enable, disable the dumping of per callsite data (one file each) (default: disabled)"},
	{0}
};


static error_t parse_opt(int key, char *arg, struct argp_state *state) {
  /* Get the input settings from argp_parse, which we
   * know is a pointer to our settings structure. */
  struct numamma_settings *settings = state->input;

  switch(key) {
  case 'v':
    settings->verbose = 1;
    break;

  case 'r':
    settings->sampling_rate = atoi(arg);
    break;
  case 'a':
    settings->alarm = atoi(arg);
    break;
  case 'f':
    if(arg && strcmp(arg, "no")==0)
      settings->flush = 0;
    else
      settings->flush = 1;
    break;
  case 's':
    settings->buffer_size = atoi(arg);
    break;
  case 'c':
    settings->canary_check = 1;
    break;
			
  case 'o':
    settings->output_dir = arg;
    break;
  case 'm':
    if(arg && strcmp(arg, "no")==0)
      settings->match_samples = 0;
    else
      settings->match_samples = 1;
    break;
  case ONLINE_ANALYSIS:
    settings->online_analysis = 1;
    break;
  case 'd':
    settings->dump = 1;
    break;
  case 'D':
    settings->dump_all = 1;
    break;
  case 'u':
    settings->dump_unmatched = 1;
    break;
  case 'n':
    settings->dump_single_items = 0;
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

int main(int argc, char **argv) {
  struct numamma_settings settings;

  // Default values
  settings.verbose = SETTINGS_VERBOSE_DEFAULT;

  settings.sampling_rate = SETTINGS_SAMPLING_RATE_DEFAULT;
  settings.alarm = SETTINGS_ALARM_DEFAULT;
  settings.flush = SETTINGS_FLUSH_DEFAULT;
  settings.buffer_size = SETTINGS_BUFFER_SIZE_DEFAULT;
  settings.canary_check = SETTINGS_CANARY_CHECK_DEFAULT;

  settings.output_dir = malloc(STRING_LENGTH);
  snprintf(settings.output_dir, STRING_LENGTH, "/tmp/numamma_%s", getenv("USER"));
  settings.match_samples = SETTINGS_MATCH_SAMPLES_DEFAULT;
  settings.online_analysis = SETTINGS_ONLINE_ANALYSIS_DEFAULT;
  settings.dump_all = SETTINGS_DUMP_ALL_DEFAULT;
  settings.dump = SETTINGS_DUMP_DEFAULT;
  settings.dump_unmatched = SETTINGS_DUMP_UNMATCHED_DEFAULT;
  settings.dump_single_items = SETTINGS_DUMP_SINGLE_ITEMS;

  // first divide argv between numamma options and target file and options
  // optionnal todo : better target detection : it should be possible to specify both --option=value and --option value, but for now the latter is not interpreted as such
  int target_i = 1;
  while (target_i < argc && argv[target_i][0] == '-') target_i++;
  if (target_i == argc)
    {
      // there are no settings, either the user entered --help or something like that, either we want to print usage anyway
      return argp_parse(&argp, argc, argv, 0, 0, &settings);
    }
	
  char **target_argv = NULL;
  if (target_i < argc)
    target_argv = &(argv[target_i]);
  // we only want to parse what comes before target included
  argp_parse(&argp, target_i+1, argv, 0, 0, &settings);

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

#define setenv_format(var, format, value, overwrite) do {	\
    char str[STRING_LEN];			\
    snprintf(str, STRING_LEN, format, value);	\
    setenv(var, str, overwrite);		\
  }while(0)
#define setenv_int(var, value, overwrite) 	\
  setenv_format(var, "%d", value, overwrite)
#define setenv_size_t(var, value, overwrite) 	\
  setenv_format(var, "%zu", value, overwrite)

  setenv_int("NUMAMMA_VERBOSE", settings.verbose, 1);
  setenv_int("NUMAMMA_SAMPLING_RATE", settings.sampling_rate, 1);
  setenv_int("NUMAMMA_ALARM", settings.alarm, 1);
  setenv_int("NUMAMMA_FLUSH", settings.flush, 1);
  setenv_size_t("NUMAMMA_BUFFER_SIZE", settings.buffer_size, 1);
  setenv_int("NUMAMMA_CANARY_CHECK", settings.canary_check, 1);

  setenv("NUMAMMA_OUTPUT_DIR", settings.output_dir, 1);
  setenv_int("NUMAMMA_MATCH_SAMPLES", settings.match_samples, 1);
  setenv_int("NUMAMMA_ONLINE_ANALYSIS", settings.online_analysis, 1);
  setenv_int("NUMAMMA_DUMP_ALL", settings.dump_all, 1);
  setenv_int("NUMAMMA_DUMP", settings.dump, 1);
  setenv_int("NUMAMMA_DUMP_UNMATCHED", settings.dump_unmatched, 1);
  setenv_int("NUMAMMA_DUMP_SINGLE_ITEMS", settings.dump_single_items, 1);

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
