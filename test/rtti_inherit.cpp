// Three-level inheritance chain with polymorphism.
// Shape -> Polygon -> Rectangle -> Square
// Tests: _ZTI chain depth, base_classes at each level, vtable slot inheritance,
//        pure virtual methods, and override resolution.
#include <cstdio>
#include <cmath>

class Shape {
public:
    virtual ~Shape() {}
    virtual const char* name() const = 0;       // pure virtual
    virtual double area() const = 0;            // pure virtual
    virtual double perimeter() const = 0;       // pure virtual
    virtual void describe() const {
        printf("%s: area=%.2f perimeter=%.2f\n", name(), area(), perimeter());
    }
};

class Polygon : public Shape {
public:
    int sides;
    explicit Polygon(int s) : sides(s) {}
    virtual ~Polygon() {}
    const char* name() const override { return "Polygon"; }
    double area() const override { return 0.0; }
    double perimeter() const override { return 0.0; }
    virtual int num_sides() const { return sides; }
};

class Rectangle : public Polygon {
public:
    double width, height;
    Rectangle(double w, double h) : Polygon(4), width(w), height(h) {}
    virtual ~Rectangle() {}
    const char* name() const override { return "Rectangle"; }
    double area() const override { return width * height; }
    double perimeter() const override { return 2.0 * (width + height); }
    virtual double diagonal() const { return sqrt(width * width + height * height); }
};

class Square : public Rectangle {
public:
    explicit Square(double side) : Rectangle(side, side) {}
    virtual ~Square() {}
    const char* name() const override { return "Square"; }
    // diagonal() inherited from Rectangle — vtable slot shared, not overridden
};

static void print_shape(const Shape& s) {
    s.describe();
}

int main() {
    Polygon poly(6);
    Rectangle rect(3.0, 4.0);
    Square sq(5.0);

    print_shape(poly);
    print_shape(rect);
    print_shape(sq);

    printf("rect diagonal=%.2f\n", rect.diagonal());
    printf("sq  diagonal=%.2f\n", sq.diagonal());

    // Polymorphic array exercises vtable dispatch
    Shape* shapes[3] = { &poly, &rect, &sq };
    for (int i = 0; i < 3; ++i)
        shapes[i]->describe();

    return 0;
}
