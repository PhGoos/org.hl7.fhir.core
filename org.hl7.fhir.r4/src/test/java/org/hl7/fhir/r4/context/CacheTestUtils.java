package org.hl7.fhir.r4.context;

import org.hl7.fhir.utilities.FhirPublication;
import org.hl7.fhir.utilities.validation.ValidationOptions;

public class CacheTestUtils {
  public static final ValidationOptions validationOptions = new ValidationOptions(FhirPublication.R4).withGuessSystem()
      .withVersionFlexible(false);

}
