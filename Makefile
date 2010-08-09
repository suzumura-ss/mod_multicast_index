APXS=apxs
# APXS_FLAGS=-Wc,-Wall -Wc,-g -Wc,-O3 -Wl,-lcurl
APXS_FLAGS=-Wc,-Wall -Wc,-g -Wc,-O0 -Wl

TARGET=mod_multicast_index.slo
SRC=mod_multicast_index.c
HEADERS=

all: $(TARGET)

$(TARGET): $(SRC) $(HEADERS)
	$(APXS) -c $(APXS_FLAGS) $(SRC)

install:: $(SRC) $(HEADERS)
	$(APXS) -i -c $(APXS_FLAGS) $(SRC)

clean:
	@rm -f $(TARGET:slo=*o) $(TARGET:slo=*a)
