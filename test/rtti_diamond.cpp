// Diamond inheritance with virtual base classes.
//
//         Vehicle   (base)
//        /        \
//      Car        Boat      (virtual inheritance from Vehicle)
//        \        /
//        Amphibious         (inherits from Car and Boat)
//
// Virtual inheritance ensures Vehicle's subobject is shared, producing:
//   __vmi_class_type_info for Car, Boat, and Amphibious
//   __si_class_type_info for Vehicle (or __class_type_info if truly standalone)
//
// Tests: has_multiple_inheritance, has_virtual_inheritance flags, vptr layout
//        (Amphibious has two vptrs — one for Car, one for Boat), and that
//        base_classes for Amphibious lists both Car and Boat.
#include <cstdio>

class Vehicle {
public:
    int max_speed;
    explicit Vehicle(int spd) : max_speed(spd) {}
    virtual ~Vehicle() {}
    virtual const char* kind() const { return "Vehicle"; }
    virtual void move() const { printf("Vehicle moving at %d\n", max_speed); }
};

class Car : public virtual Vehicle {
public:
    int num_wheels;
    Car(int spd, int wheels) : Vehicle(spd), num_wheels(wheels) {}
    virtual ~Car() {}
    const char* kind() const override { return "Car"; }
    void move() const override { printf("Car driving at %d on %d wheels\n", max_speed, num_wheels); }
    virtual void honk() const { printf("Beep!\n"); }
};

class Boat : public virtual Vehicle {
public:
    double displacement;
    Boat(int spd, double disp) : Vehicle(spd), displacement(disp) {}
    virtual ~Boat() {}
    const char* kind() const override { return "Boat"; }
    void move() const override { printf("Boat sailing at %d, displacement=%.1f t\n", max_speed, displacement); }
    virtual void horn() const { printf("Honk!\n"); }
};

class Amphibious : public Car, public Boat {
public:
    Amphibious(int spd, int wheels, double disp)
        : Vehicle(spd), Car(spd, wheels), Boat(spd, disp) {}
    virtual ~Amphibious() {}
    const char* kind() const override { return "Amphibious"; }
    void move() const override {
        printf("Amphibious at %d: wheels=%d disp=%.1f\n", max_speed, num_wheels, displacement);
    }
};

static void describe(Vehicle& v) {
    printf("kind=%s\n", v.kind());
    v.move();
}

int main() {
    Vehicle veh(60);
    Car car(120, 4);
    Boat boat(40, 1.5);
    Amphibious amph(80, 4, 2.0);

    describe(veh);
    describe(car);
    describe(boat);
    describe(amph);

    car.honk();
    boat.horn();

    // Access via Car* and Boat* base pointers to exercise both vptrs
    Car*  as_car  = &amph;
    Boat* as_boat = &amph;
    as_car->honk();
    as_boat->horn();

    return 0;
}
