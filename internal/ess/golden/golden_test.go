package golden

import "testing"

func TestEmbeddedGolden(t *testing.T) {
	res, err := Run(Embedded())
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 16 {
		t.Fatalf("벡터 %d건 (기대 16)", len(res))
	}
	for _, r := range res {
		if !r.Pass {
			t.Errorf("%s 실패: %+v", r.CaseID, r)
		}
	}
}
