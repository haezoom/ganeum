package jcs

import (
	"encoding/json"
	"testing"
)

func TestCanonical(t *testing.T) {
	cases := []struct{ in, want string }{
		{`{"b":1,"a":[3,{"z":true,"y":null}],"c":"x"}`, `{"a":[3,{"y":null,"z":true}],"b":1,"c":"x"}`},
		{`{"s":"\u0001\"\\/é"}`, "{\"s\":\"\\u0001\\\"\\\\/é\"}"},
		{`{"n":-0,"m":1781000000900}`, `{"m":1781000000900,"n":0}`},
		{`{"\u20ac":1,"\r":2,"1":3}`, "{\"\\r\":2,\"1\":3,\"€\":1}"},
		{`{"override_polarity_gap":false}`, `{"override_polarity_gap":false}`},
	}
	for _, c := range cases {
		var v any
		d := json.NewDecoder(stringsReader(c.in))
		d.UseNumber()
		if err := d.Decode(&v); err != nil {
			t.Fatal(err)
		}
		got, err := Marshal(v)
		if err != nil {
			t.Fatalf("%s: %v", c.in, err)
		}
		if string(got) != c.want {
			t.Errorf("JCS(%s) = %s, want %s", c.in, got, c.want)
		}
	}
}

func TestRejectsFraction(t *testing.T) {
	if _, err := Marshal(map[string]any{"p": json.Number("1.5")}); err == nil {
		t.Fatal("expected error for non-integer")
	}
}
