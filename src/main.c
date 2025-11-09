#include <ndpi_main.h>
#include <stdio.h>

int main() {
  // main state structure for the nDPI engine
  struct ndpi_detection_module_struct *ndpi_struct = NULL;
  ndpi_cfg_error rc;

  // core allocation and basic initialization
  // NULL - NOT a shared global context (fine for single thread)
  ndpi_struct = ndpi_init_detection_module(NULL);
  if (!ndpi_struct) {
    // Handle allocation error
    fprintf(stderr, "Error: ndpi_init_detection_module failed.\n");
    return 1;
  }

  // Allows setting runtime parameters
  // rc = ndpi_set_config()

  // Finalize the internal setup
  int ret = ndpi_finalize_initialization(ndpi_struct);
  if (ret != 0) {
    fprintf(stderr, "Error: ndpi_finalize_initialization failed with return code %d.\n", ret);
    // Clean up already initialized module before exiting
    ndpi_exit_detection_module(ndpi_struct); 
    return 1;
  }

  printf("nDPI initialization complete. Ready for packet processing.\n");

  // Start processing packets


  ndpi_exit_detection_module(ndpi_struct);

  return 0;
}
