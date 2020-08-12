package com.danielfarias.CursoSpringSecurity.student;

import java.util.Arrays;
import java.util.List;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api/v1/students")
public class StudentController {
	
	private static final List<Student> STUDENTS = Arrays.asList(
			new Student(1, "Daniel Farias"),
			new Student(2, "Izabel Farias"),
			new Student(3, "Luiziane Farias"),
			new Student (4, "Felipe Farias")
	);
	
	@GetMapping(path="/{studentId}")
	public Student getStudent(@PathVariable("studentId") Integer studentId) {
		return STUDENTS.stream().filter(student -> studentId.equals(student.getStudentId()))
				.findFirst()
				.orElseThrow(() -> new IllegalStateException("Student " + studentId + " does not exists"));
	}

}
