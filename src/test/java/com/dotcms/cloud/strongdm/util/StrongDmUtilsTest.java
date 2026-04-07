package com.dotcms.cloud.strongdm.util;

import java.io.IOException;
import java.util.Map;
import org.junit.Test;

public class StrongDmUtilsTest {

    
    String jwtToken="testing";
    
    
    @Test
    public void test_validateAndParseToken() throws IOException {
        StrongDmUtils utils = new StrongDmUtils();
        
        
        Map<String,String> parsedToken = utils.validateAndParseToken(jwtToken);
        
        
        
        
        
        
    }

}
