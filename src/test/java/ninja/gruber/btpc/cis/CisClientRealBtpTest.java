// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.cis;
import ninja.gruber.btpc.cis.domain.SubaccountCandidate;

import com.fasterxml.jackson.databind.ObjectMapper;
import ninja.gruber.btpc.support.Allowlists;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

//local tests for my service keys
@EnabledIfEnvironmentVariable(named = "BTPC_TEST_REAL_BTP", matches = "1")
class CisClientRealBtpTest {

    //*old as cv-key now used
    @Test
    void listSubaccounts_realLocalKey() throws Exception {
        Path keyPath = Path.of("").toAbsolutePath().resolve("sklocal-cis.json");
        if (!Files.exists(keyPath)) {
            System.err.println("skipping: sklocal-cis.json not present");
            return;
        }
        run("LOCAL", Files.readString(keyPath));
    }

    @Test
    void listSubaccounts_realCentralKey() throws Exception {
        Path keyPath = Path.of("").toAbsolutePath().resolve("skcentral-cis.json");
        if (!Files.exists(keyPath)) {
            System.err.println("skipping: skcentral-cis.json not present");
            return;
        }
        run("CENTRAL", Files.readString(keyPath));
    }

    private static void run(String label, String json) {
        CisClient cis = new CisClient(new ObjectMapper(), new CisTokenCache(), Allowlists.permissive());
        System.out.println("==================== " + label + " key ====================");
        try {
            List<SubaccountCandidate> r = cis.listSubaccounts(json);
            System.out.println(label + " OK: " + r.size() + " subaccount(s)");
            for (SubaccountCandidate s : r) {
                System.out.println("  guid=" + s.guid() +
                        "  displayName=" + s.displayName() +
                        "  region=" + s.region() +
                        "  parentType=" + s.parentType() +
                        "  parentGUID=" + s.parentGuid() +
                        "  state=" + s.state());
            }
        } catch (CisException e) {
            System.err.println(label + " FAILED");
            System.err.println("  message       : " + e.getMessage());
            System.err.println("  upstream code : " + e.upstreamStatus());
            System.err.println("  upstream body : " + e.upstreamBody());
        } catch (Exception e) {
            System.err.println(label + " UNEXPECTED EXCEPTION: " + e);
        }
    }
}
